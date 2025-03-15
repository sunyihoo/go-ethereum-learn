// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// Package utils contains internal helper functions for go-ethereum commands.
package utils

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/eth/ethconfig"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/debug"
	"github.com/ethereum/go-ethereum/internal/era"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/urfave/cli/v2"
)

const (
	importBatchSize = 2500
)

// Fatalf formats a message to standard error and exits the program.
// The message is also printed to standard output if standard error
// is redirected to a different file.
func Fatalf(format string, args ...interface{}) {
	w := io.MultiWriter(os.Stdout, os.Stderr)
	if runtime.GOOS == "windows" {
		// The SameFile check below doesn't work on Windows.
		// stdout is unlikely to get redirected though, so just print there.
		w = os.Stdout
	} else {
		outf, _ := os.Stdout.Stat()
		errf, _ := os.Stderr.Stat()
		if outf != nil && errf != nil && os.SameFile(outf, errf) {
			w = os.Stderr
		}
	}
	fmt.Fprintf(w, "Fatal: "+format+"\n", args...)
	os.Exit(1)
}

func StartNode(ctx *cli.Context, stack *node.Node, isConsole bool) {
	if err := stack.Start(); err != nil {
		Fatalf("Error starting protocol stack: %v", err)
	}
	go func() {
		sigc := make(chan os.Signal, 1)
		signal.Notify(sigc, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigc)

		minFreeDiskSpace := 2 * ethconfig.Defaults.TrieDirtyCache // Default 2 * 256Mb
		if ctx.IsSet(MinFreeDiskSpaceFlag.Name) {
			minFreeDiskSpace = ctx.Int(MinFreeDiskSpaceFlag.Name)
		} else if ctx.IsSet(CacheFlag.Name) || ctx.IsSet(CacheGCFlag.Name) {
			minFreeDiskSpace = 2 * ctx.Int(CacheFlag.Name) * ctx.Int(CacheGCFlag.Name) / 100
		}
		if minFreeDiskSpace > 0 {
			go monitorFreeDiskSpace(sigc, stack.InstanceDir(), uint64(minFreeDiskSpace)*1024*1024)
		}

		shutdown := func() {
			log.Info("Got interrupt, shutting down...")
			go stack.Close()
			for i := 10; i > 0; i-- {
				<-sigc
				if i > 1 {
					log.Warn("Already shutting down, interrupt more to panic.", "times", i-1)
				}
			}
			debug.Exit() // ensure trace and CPU profile data is flushed.
			debug.LoudPanic("boom")
		}

		if isConsole {
			// In JS console mode, SIGINT is ignored because it's handled by the console.
			// However, SIGTERM still shuts down the node.
			for {
				sig := <-sigc
				if sig == syscall.SIGTERM {
					shutdown()
					return
				}
			}
		} else {
			<-sigc
			shutdown()
		}
	}()
}

func monitorFreeDiskSpace(sigc chan os.Signal, path string, freeDiskSpaceCritical uint64) {
	if path == "" {
		return
	}
	for {
		freeSpace, err := getFreeDiskSpace(path)
		if err != nil {
			log.Warn("Failed to get free disk space", "path", path, "err", err)
			break
		}
		if freeSpace < freeDiskSpaceCritical {
			log.Error("Low disk space. Gracefully shutting down Geth to prevent database corruption.", "available", common.StorageSize(freeSpace), "path", path)
			sigc <- syscall.SIGTERM
			break
		} else if freeSpace < 2*freeDiskSpaceCritical {
			log.Warn("Disk space is running low. Geth will shutdown if disk space runs below critical level.", "available", common.StorageSize(freeSpace), "critical_level", common.StorageSize(freeDiskSpaceCritical), "path", path)
		}
		time.Sleep(30 * time.Second)
	}
}

func ImportChain(chain *core.BlockChain, fn string) error {
	// Watch for Ctrl-C while the import is running.
	// If a signal is received, the import will stop at the next batch.
	interrupt := make(chan os.Signal, 1)
	stop := make(chan struct{})
	signal.Notify(interrupt, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(interrupt)
	defer close(interrupt)
	go func() {
		if _, ok := <-interrupt; ok {
			log.Info("Interrupted during import, stopping at next batch")
		}
		close(stop)
	}()
	checkInterrupt := func() bool {
		select {
		case <-stop:
			return true
		default:
			return false
		}
	}

	log.Info("Importing blockchain", "file", fn)

	// Open the file handle and potentially unwrap the gzip stream
	fh, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fh.Close()

	var reader io.Reader = fh
	if strings.HasSuffix(fn, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return err
		}
	}
	stream := rlp.NewStream(reader, 0)

	// Run actual the import.
	blocks := make(types.Blocks, importBatchSize)
	n := 0

	for batch := 0; ; batch++ {
		// Load a batch of RLP blocks.
		if checkInterrupt() {
			return errors.New("interrupted")
		}
		i := 0
		for ; i < importBatchSize; i++ {
			var b types.Block
			if err := stream.Decode(&b); err == io.EOF {
				break
			} else if err != nil {
				return fmt.Errorf("at block %d: %v", n, err)
			}
			// don't import first block
			if b.NumberU64() == 0 {
				i--
				continue
			}
			blocks[i] = &b
			n++
		}
		if i == 0 {
			break
		}
		// Import the batch.
		if checkInterrupt() {
			return errors.New("interrupted")
		}
		missing := missingBlocks(chain, blocks[:i])
		if len(missing) == 0 {
			log.Info("Skipping batch as all blocks present", "batch", batch, "first", blocks[0].Hash(), "last", blocks[i-1].Hash())
			continue
		}
		if failindex, err := chain.InsertChain(missing); err != nil {
			var failnumber uint64
			if failindex > 0 && failindex < len(missing) {
				failnumber = missing[failindex].NumberU64()
			} else {
				failnumber = missing[0].NumberU64()
			}
			return fmt.Errorf("invalid block %d: %v", failnumber, err)
		}
	}
	return nil
}

func readList(filename string) ([]string, error) {
	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(b), "\n"), nil
}

// ImportHistory imports Era1 files containing historical block information,
// starting from genesis.
func ImportHistory(chain *core.BlockChain, db ethdb.Database, dir string, network string) error {
	if chain.CurrentSnapBlock().Number.BitLen() != 0 {
		return errors.New("history import only supported when starting from genesis")
	}
	entries, err := era.ReadDir(dir, network)
	if err != nil {
		return fmt.Errorf("error reading %s: %w", dir, err)
	}
	checksums, err := readList(filepath.Join(dir, "checksums.txt"))
	if err != nil {
		return fmt.Errorf("unable to read checksums.txt: %w", err)
	}
	if len(checksums) != len(entries) {
		return fmt.Errorf("expected equal number of checksums and entries, have: %d checksums, %d entries", len(checksums), len(entries))
	}
	var (
		start    = time.Now()
		reported = time.Now()
		imported = 0
		h        = sha256.New()
		buf      = bytes.NewBuffer(nil)
	)
	for i, filename := range entries {
		err := func() error {
			f, err := os.Open(filepath.Join(dir, filename))
			if err != nil {
				return fmt.Errorf("unable to open era: %w", err)
			}
			defer f.Close()

			// Validate checksum.
			if _, err := io.Copy(h, f); err != nil {
				return fmt.Errorf("unable to recalculate checksum: %w", err)
			}
			if have, want := common.BytesToHash(h.Sum(buf.Bytes()[:])).Hex(), checksums[i]; have != want {
				return fmt.Errorf("checksum mismatch: have %s, want %s", have, want)
			}
			h.Reset()
			buf.Reset()

			// Import all block data from Era1.
			e, err := era.From(f)
			if err != nil {
				return fmt.Errorf("error opening era: %w", err)
			}
			it, err := era.NewIterator(e)
			if err != nil {
				return fmt.Errorf("error making era reader: %w", err)
			}
			for it.Next() {
				block, err := it.Block()
				if err != nil {
					return fmt.Errorf("error reading block %d: %w", it.Number(), err)
				}
				if block.Number().BitLen() == 0 {
					continue // skip genesis
				}
				receipts, err := it.Receipts()
				if err != nil {
					return fmt.Errorf("error reading receipts %d: %w", it.Number(), err)
				}
				if status, err := chain.HeaderChain().InsertHeaderChain([]*types.Header{block.Header()}, start); err != nil {
					return fmt.Errorf("error inserting header %d: %w", it.Number(), err)
				} else if status != core.CanonStatTy {
					return fmt.Errorf("error inserting header %d, not canon: %v", it.Number(), status)
				}
				if _, err := chain.InsertReceiptChain([]*types.Block{block}, []types.Receipts{receipts}, 2^64-1); err != nil {
					return fmt.Errorf("error inserting body %d: %w", it.Number(), err)
				}
				imported += 1

				// Give the user some feedback that something is happening.
				if time.Since(reported) >= 8*time.Second {
					log.Info("Importing Era files", "head", it.Number(), "imported", imported, "elapsed", common.PrettyDuration(time.Since(start)))
					imported = 0
					reported = time.Now()
				}
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}

	return nil
}

// ExportChain exports a blockchain into the specified file, truncating any data
// already present in the file.
func ExportChain(blockchain *core.BlockChain, fn string) error {
	log.Info("Exporting blockchain", "file", fn)

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the blocks and export them
	if err := blockchain.Export(writer); err != nil {
		return err
	}
	log.Info("Exported blockchain", "file", fn)

	return nil
}

// ExportAppendChain exports a blockchain into the specified file, appending to
// the file if data already exists in it.
func ExportAppendChain(blockchain *core.BlockChain, fn string, first uint64, last uint64) error {
	log.Info("Exporting blockchain", "file", fn)

	// Open the file handle and potentially wrap with a gzip stream
	fh, err := os.OpenFile(fn, os.O_CREATE|os.O_APPEND|os.O_WRONLY, os.ModePerm)
	if err != nil {
		return err
	}
	defer fh.Close()

	var writer io.Writer = fh
	if strings.HasSuffix(fn, ".gz") {
		writer = gzip.NewWriter(writer)
		defer writer.(*gzip.Writer).Close()
	}
	// Iterate over the blocks and export them
	if err := blockchain.ExportN(writer, first, last); err != nil {
		return err
	}
	log.Info("Exported blockchain to", "file", fn)
	return nil
}

// ExportHistory exports blockchain history into the specified directory,
// following the Era format.
func ExportHistory(bc *core.BlockChain, dir string, first, last, step uint64) error {
	log.Info("Exporting blockchain history", "dir", dir)
	if head := bc.CurrentBlock().Number.Uint64(); head < last {
		log.Warn("Last block beyond head, setting last = head", "head", head, "last", last)
		last = head
	}
	network := "unknown"
	if name, ok := params.NetworkNames[bc.Config().ChainID.String()]; ok {
		network = name
	}
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return fmt.Errorf("error creating output directory: %w", err)
	}
	var (
		start     = time.Now()
		reported  = time.Now()
		h         = sha256.New()
		buf       = bytes.NewBuffer(nil)
		checksums []string
	)
	for i := first; i <= last; i += step {
		err := func() error {
			filename := filepath.Join(dir, era.Filename(network, int(i/step), common.Hash{}))
			f, err := os.Create(filename)
			if err != nil {
				return fmt.Errorf("could not create era file: %w", err)
			}
			defer f.Close()

			w := era.NewBuilder(f)
			for j := uint64(0); j < step && j <= last-i; j++ {
				var (
					n     = i + j
					block = bc.GetBlockByNumber(n)
				)
				if block == nil {
					return fmt.Errorf("export failed on #%d: not found", n)
				}
				receipts := bc.GetReceiptsByHash(block.Hash())
				if receipts == nil {
					return fmt.Errorf("export failed on #%d: receipts not found", n)
				}
				td := bc.GetTd(block.Hash(), block.NumberU64())
				if td == nil {
					return fmt.Errorf("export failed on #%d: total difficulty not found", n)
				}
				if err := w.Add(block, receipts, td); err != nil {
					return err
				}
			}
			root, err := w.Finalize()
			if err != nil {
				return fmt.Errorf("export failed to finalize %d: %w", step/i, err)
			}
			// Set correct filename with root.
			os.Rename(filename, filepath.Join(dir, era.Filename(network, int(i/step), root)))

			// Compute checksum of entire Era1.
			if _, err := f.Seek(0, io.SeekStart); err != nil {
				return err
			}
			if _, err := io.Copy(h, f); err != nil {
				return fmt.Errorf("unable to calculate checksum: %w", err)
			}
			checksums = append(checksums, common.BytesToHash(h.Sum(buf.Bytes()[:])).Hex())
			h.Reset()
			buf.Reset()
			return nil
		}()
		if err != nil {
			return err
		}
		if time.Since(reported) >= 8*time.Second {
			log.Info("Exporting blocks", "exported", i, "elapsed", common.PrettyDuration(time.Since(start)))
			reported = time.Now()
		}
	}

	os.WriteFile(filepath.Join(dir, "checksums.txt"), []byte(strings.Join(checksums, "\n")), os.ModePerm)

	log.Info("Exported blockchain to", "dir", dir)

	return nil
}

// ImportPreimages imports a batch of exported hash preimages into the database.
// It's a part of the deprecated functionality, should be removed in the future.
func ImportPreimages(db ethdb.Database, fn string) error {
	log.Info("Importing preimages", "file", fn)

	// Open the file handle and potentially unwrap the gzip stream
	fh, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer fh.Close()

	var reader io.Reader = bufio.NewReader(fh)
	if strings.HasSuffix(fn, ".gz") {
		if reader, err = gzip.NewReader(reader); err != nil {
			return err
		}
	}
	stream := rlp.NewStream(reader, 0)

	// Import the preimages in batches to prevent disk thrashing
	preimages := make(map[common.Hash][]byte)

	for {
		// Read the next entry and ensure it's not junk
		var blob []byte

		if err := stream.Decode(&blob); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
		// Accumulate the preimages and flush when enough ws gathered
		preimages[crypto.Keccak256Hash(blob)] = common.CopyBytes(blob)
		if len(preimages) > 1024 {
			rawdb.WritePreimages(db, preimages)
			preimages = make(map[common.Hash][]byte)
		}
	}
	// Flush the last batch preimage data
	if len(preimages) > 0 {
		rawdb.WritePreimages(db, preimages)
	}
	return nil
}

func missingBlocks(chain *core.BlockChain, blocks []*types.Block) []*types.Block {
	head := chain.CurrentBlock()
	for i, block := range blocks {
		// If we're behind the chain head, only check block, state is available at head
		if head.Number.Uint64() > block.NumberU64() {
			if !chain.HasBlock(block.Hash(), block.NumberU64()) {
				return blocks[i:]
			}
			continue
		}
		// If we're above the chain head, state availability is a must
		if !chain.HasBlockAndState(block.Hash(), block.NumberU64()) {
			return blocks[i:]
		}
	}
	return nil
}
