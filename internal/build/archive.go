// Copyright 2016 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package build

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Archive interface {
	// Directory adds a new directory entry to the archive and sets the
	// directory for subsequent calls to Header.
	// Directory 将一个新的目录条目添加到归档中，并为后续的Header调用设置目录。
	Directory(name string) error

	// Header adds a new file to the archive. The file is added to the directory
	// set by Directory. The content of the file must be written to the returned
	// writer.
	// Header 将一个新文件添加到归档中。文件将被添加到由Directory设置的目录中。文件内容必须写入返回的写入器。
	Header(os.FileInfo) (io.Writer, error)

	// Close flushes the archive and closes the underlying file.
	// Close 刷新归档并关闭底层文件。
	Close() error
}

func NewArchive(file *os.File) (Archive, string) {
	switch {
	case strings.HasSuffix(file.Name(), ".zip"):
		return NewZipArchive(file), strings.TrimSuffix(file.Name(), ".zip")
	case strings.HasSuffix(file.Name(), ".tar.gz"):
		return NewTarballArchive(file), strings.TrimSuffix(file.Name(), ".tar.gz")
	default:
		return nil, ""
	}
}

// AddFile appends an existing file to an archive.
// AddFile 将一个现有文件追加到归档中。
func AddFile(a Archive, file string) error {
	fd, err := os.Open(file)
	if err != nil {
		return err
	}
	defer fd.Close()
	fi, err := fd.Stat()
	if err != nil {
		return err
	}
	w, err := a.Header(fi)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, fd); err != nil {
		return err
	}
	return nil
}

// WriteArchive creates an archive containing the given files.
// WriteArchive 创建一个包含给定文件的归档。
func WriteArchive(name string, files []string) (err error) {
	archfd, err := os.Create(name)
	if err != nil {
		return err
	}

	defer func() {
		archfd.Close()
		// Remove the half-written archive on failure.
		// 如果失败，删除半写的归档文件。
		if err != nil {
			os.Remove(name)
		}
	}()
	archive, basename := NewArchive(archfd)
	if archive == nil {
		return errors.New("unknown archive extension")
	}
	fmt.Println(name)
	if err := archive.Directory(basename); err != nil {
		return err
	}
	for _, file := range files {
		fmt.Println("   +", filepath.Base(file))
		if err := AddFile(archive, file); err != nil {
			return err
		}
	}
	return archive.Close()
}

type ZipArchive struct {
	dir  string
	zipw *zip.Writer
	file io.Closer
}

func NewZipArchive(w io.WriteCloser) Archive {
	return &ZipArchive{"", zip.NewWriter(w), w}
}

func (a *ZipArchive) Directory(name string) error {
	a.dir = name + "/"
	return nil
}

func (a *ZipArchive) Header(fi os.FileInfo) (io.Writer, error) {
	head, err := zip.FileInfoHeader(fi)
	if err != nil {
		return nil, fmt.Errorf("can't make zip header: %v", err)
	}
	head.Name = a.dir + head.Name
	head.Method = zip.Deflate
	w, err := a.zipw.CreateHeader(head)
	if err != nil {
		return nil, fmt.Errorf("can't add zip header: %v", err)
	}
	return w, nil
}

func (a *ZipArchive) Close() error {
	if err := a.zipw.Close(); err != nil {
		return err
	}
	return a.file.Close()
}

type TarballArchive struct {
	dir  string
	tarw *tar.Writer
	gzw  *gzip.Writer
	file io.Closer
}

func NewTarballArchive(w io.WriteCloser) Archive {
	gzw := gzip.NewWriter(w)
	tarw := tar.NewWriter(gzw)
	return &TarballArchive{"", tarw, gzw, w}
}

func (a *TarballArchive) Directory(name string) error {
	a.dir = name + "/"
	return a.tarw.WriteHeader(&tar.Header{
		Name:     a.dir,
		Mode:     0755,
		Typeflag: tar.TypeDir,
		ModTime:  time.Now(),
	})
}

func (a *TarballArchive) Header(fi os.FileInfo) (io.Writer, error) {
	head, err := tar.FileInfoHeader(fi, "")
	if err != nil {
		return nil, fmt.Errorf("can't make tar header: %v", err)
	}
	head.Name = a.dir + head.Name
	if err := a.tarw.WriteHeader(head); err != nil {
		return nil, fmt.Errorf("can't add tar header: %v", err)
	}
	return a.tarw, nil
}

func (a *TarballArchive) Close() error {
	if err := a.tarw.Close(); err != nil {
		return err
	}
	if err := a.gzw.Close(); err != nil {
		return err
	}
	return a.file.Close()
}

// ExtractArchive unpacks a .zip or .tar.gz archive to the destination directory.
// ExtractArchive 将 .zip 或 .tar.gz 归档解压到目标目录。
func ExtractArchive(archive string, dest string) error {
	ar, err := os.Open(archive)
	if err != nil {
		return err
	}
	defer ar.Close()

	switch {
	case strings.HasSuffix(archive, ".tar.gz"):
		return extractTarball(ar, dest)
	case strings.HasSuffix(archive, ".zip"):
		return extractZip(ar, dest)
	default:
		return fmt.Errorf("unhandled archive type %s", archive)
	}
}

// extractTarball unpacks a .tar.gz file.
// extractTarball 解压一个 .tar.gz 文件。
func extractTarball(ar io.Reader, dest string) error {
	gzr, err := gzip.NewReader(ar)
	if err != nil {
		return err
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		// Move to the next file header.
		// 移动到下一个文件头。
		header, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		// We only care about regular files, directory modes
		// and special file types are not supported.
		// 我们只关心常规文件，目录模式和特殊文件类型不受支持。
		if header.Typeflag == tar.TypeReg {
			armode := header.FileInfo().Mode()
			err := extractFile(header.Name, armode, tr, dest)
			if err != nil {
				return fmt.Errorf("extract %s: %v", header.Name, err)
			}
		}
	}
}

// extractZip unpacks the given .zip file.
// extractZip 解压给定的 .zip 文件。
func extractZip(ar *os.File, dest string) error {
	info, err := ar.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(ar, info.Size())
	if err != nil {
		return err
	}

	for _, zf := range zr.File {
		if !zf.Mode().IsRegular() {
			continue
		}

		data, err := zf.Open()
		if err != nil {
			return err
		}
		err = extractFile(zf.Name, zf.Mode(), data, dest)
		data.Close()
		if err != nil {
			return fmt.Errorf("extract %s: %v", zf.Name, err)
		}
	}
	return nil
}

// extractFile extracts a single file from an archive.
// extractFile 从归档中提取单个文件。
func extractFile(arpath string, armode os.FileMode, data io.Reader, dest string) error {
	// Check that path is inside destination directory.
	// 检查路径是否在目标目录内。
	target := filepath.Join(dest, filepath.FromSlash(arpath))
	if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) {
		return fmt.Errorf("path %q escapes archive destination", target)
	}

	// Remove the previously-extracted file if it exists
	// 如果存在之前解压的文件，则删除它。
	if err := os.RemoveAll(target); err != nil {
		return err
	}

	// Recreate the destination directory
	// 重新创建目标目录。
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}

	// Copy file data.
	// 复制文件数据。
	file, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY, armode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(file, data); err != nil {
		file.Close()
		os.Remove(target)
		return err
	}
	return file.Close()
}
