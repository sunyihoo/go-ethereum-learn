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
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"
)

var DryRunFlag = flag.Bool("n", false, "dry run, don't execute commands")

// DryRunFlag 是一个命令行标志，用于指示是否启用“干运行”模式（即不实际执行命令）。

// MustRun executes the given command and exits the host process for
// any error.
// MustRun 执行给定的命令，并在发生任何错误时终止主机进程。
func MustRun(cmd *exec.Cmd) {
	fmt.Println(">>>", printArgs(cmd.Args)) // 打印命令及其参数
	if !*DryRunFlag {                       // 如果未启用“干运行”模式，则执行命令
		cmd.Stderr = os.Stderr // 将标准错误输出重定向到终端
		cmd.Stdout = os.Stdout // 将标准输出重定向到终端
		if err := cmd.Run(); err != nil {
			log.Fatal(err) // 如果命令执行失败，则记录错误并退出程序
		}
	}
}

// printArgs formats the command arguments into a single string.
// printArgs 将命令参数格式化为单个字符串。
func printArgs(args []string) string {
	var s strings.Builder
	for i, arg := range args {
		if i > 0 {
			s.WriteByte(' ') // 参数之间用空格分隔
		}
		if strings.IndexByte(arg, ' ') >= 0 {
			arg = strconv.QuoteToASCII(arg) // 如果参数包含空格，则使用引号包裹
		}
		s.WriteString(arg)
	}
	return s.String()
}

// MustRunCommand executes the given command with arguments.
// MustRunCommand 使用给定的参数执行命令。
func MustRunCommand(cmd string, args ...string) {
	MustRun(exec.Command(cmd, args...)) // 调用 MustRun 执行命令
}

// MustRunCommandWithOutput runs the given command, and ensures that some output will be
// printed while it runs. This is useful for CI builds where the process will be stopped
// when there is no output.
// MustRunCommandWithOutput 运行给定的命令，并确保在运行期间会打印一些输出。
// 这对于 CI 构建非常有用，因为在没有输出时构建过程可能会被停止。
func MustRunCommandWithOutput(cmd string, args ...string) {
	interval := time.NewTicker(time.Minute) // 每分钟触发一次计时器
	done := make(chan struct{})
	defer interval.Stop() // 确保计时器在函数结束时停止
	defer close(done)     // 确保通道在函数结束时关闭

	go func() {
		for {
			select {
			case <-interval.C:
				fmt.Printf("Waiting for command %q\n", cmd) // 打印等待信息
			case <-done:
				return // 如果命令完成，则退出 goroutine
			}
		}
	}()
	MustRun(exec.Command(cmd, args...)) // 执行命令
}

var warnedAboutGit bool

// RunGit runs a git subcommand and returns its output.
// The command must complete successfully.
// RunGit 运行一个 git 子命令并返回其输出。命令必须成功完成。
func RunGit(args ...string) string {
	cmd := exec.Command("git", args...) // 创建 git 命令
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr // 捕获标准输出和标准错误
	if err := cmd.Run(); err != nil {
		if e, ok := err.(*exec.Error); ok && e.Err == exec.ErrNotFound {
			if !warnedAboutGit {
				log.Println("Warning: can't find 'git' in PATH") // 如果找不到 git，则发出警告
				warnedAboutGit = true
			}
			return ""
		}
		log.Fatal(strings.Join(cmd.Args, " "), ": ", err, "\n", stderr.String()) // 记录错误并退出
	}
	return strings.TrimSpace(stdout.String()) // 返回去除空格后的输出
}

// readGitFile returns content of file in .git directory.
// readGitFile 返回 .git 目录中文件的内容。
func readGitFile(file string) string {
	content, err := os.ReadFile(filepath.Join(".git", file)) // 读取文件内容
	if err != nil {
		return "" // 如果文件不存在或读取失败，则返回空字符串
	}
	return strings.TrimSpace(string(content)) // 返回去除空格后的内容
}

// Render renders the given template file into outputFile.
// Render 将给定的模板文件渲染到输出文件中。
func Render(templateFile, outputFile string, outputPerm os.FileMode, x interface{}) {
	tpl := template.Must(template.ParseFiles(templateFile)) // 解析模板文件
	render(tpl, outputFile, outputPerm, x)                  // 渲染模板
}

// RenderString renders the given template string into outputFile.
// RenderString 将给定的模板字符串渲染到输出文件中。
func RenderString(templateContent, outputFile string, outputPerm os.FileMode, x interface{}) {
	tpl := template.Must(template.New("").Parse(templateContent)) // 解析模板字符串
	render(tpl, outputFile, outputPerm, x)                        // 渲染模板
}

// render renders the given template into outputFile.
// render 将给定的模板渲染到输出文件中。
func render(tpl *template.Template, outputFile string, outputPerm os.FileMode, x interface{}) {
	if err := os.MkdirAll(filepath.Dir(outputFile), 0755); err != nil {
		log.Fatal(err) // 如果无法创建目录，则记录错误并退出
	}
	out, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_EXCL, outputPerm)
	if err != nil {
		log.Fatal(err) // 如果无法打开文件，则记录错误并退出
	}
	if err := tpl.Execute(out, x); err != nil {
		log.Fatal(err) // 如果渲染失败，则记录错误并退出
	}
	if err := out.Close(); err != nil {
		log.Fatal(err) // 如果无法关闭文件，则记录错误并退出
	}
}

// UploadSFTP uploads files to a remote host using the sftp command line tool.
// The destination host may be specified either as [user@]host: or as a URI in
// the form sftp://[user@]host[:port].
// UploadSFTP 使用 sftp 命令行工具将文件上传到远程主机。
// 目标主机可以指定为 [user@]host: 或 sftp://[user@]host[:port] 格式。
func UploadSFTP(identityFile, host, dir string, files []string) error {
	sftp := exec.Command("sftp") // 创建 sftp 命令
	sftp.Stderr = os.Stderr      // 将标准错误输出重定向到终端
	if identityFile != "" {
		sftp.Args = append(sftp.Args, "-i", identityFile) // 添加身份文件参数
	}
	sftp.Args = append(sftp.Args, host)      // 添加目标主机参数
	fmt.Println(">>>", printArgs(sftp.Args)) // 打印命令及其参数
	if *DryRunFlag {
		return nil // 如果启用“干运行”模式，则直接返回
	}

	stdin, err := sftp.StdinPipe() // 获取标准输入管道
	if err != nil {
		return fmt.Errorf("can't create stdin pipe for sftp: %v", err)
	}
	stdout, err := sftp.StdoutPipe() // 获取标准输出管道
	if err != nil {
		return fmt.Errorf("can't create stdout pipe for sftp: %v", err)
	}
	if err := sftp.Start(); err != nil { // 启动 sftp 命令
		return err
	}
	in := io.MultiWriter(stdin, os.Stdout) // 同时写入标准输入和终端
	for _, f := range files {
		fmt.Fprintln(in, "put", f, filepath.Join(dir, filepath.Base(f))) // 发送上传命令
	}
	fmt.Fprintln(in, "exit") // 发送退出命令

	// Some issue with the PPA sftp server makes it so the server does not
	// respond properly to a 'bye', 'exit' or 'quit' from the client.
	// To work around that, we check the output, and when we see the client
	// exit command, we do a hard exit.
	// 由于某些 PPA sftp 服务器的问题，服务器可能无法正确响应客户端的 'bye'、'exit' 或 'quit' 命令。
	// 为了解决这个问题，我们检查输出，当看到客户端的退出命令时，强制终止进程。
	aborted := false
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			txt := scanner.Text()
			fmt.Println(txt)
			if txt == "sftp> exit" {
				// Give it .5 seconds to exit (server might be fixed), then
				// hard kill it from the outside
				// 给它 0.5 秒的时间退出（服务器可能已修复），然后从外部强制终止进程
				time.Sleep(500 * time.Millisecond)
				aborted = true
				sftp.Process.Kill()
			}
		}
	}()
	stdin.Close()     // 关闭标准输入
	err = sftp.Wait() // 等待命令完成
	if aborted {
		return nil // 如果已强制终止，则返回 nil
	}
	return err
}

// FindMainPackages finds all 'main' packages in the given directory and returns their
// package paths.
// FindMainPackages 查找给定目录中的所有 'main' 包并返回它们的包路径。
func FindMainPackages(dir string) []string {
	var commands []string
	cmds, err := os.ReadDir(dir) // 读取目录内容
	if err != nil {
		log.Fatal(err) // 如果读取失败，则记录错误并退出
	}
	for _, cmd := range cmds {
		pkgdir := filepath.Join(dir, cmd.Name())
		if !cmd.IsDir() {
			continue // 如果不是目录，则跳过
		}
		pkgs, err := parser.ParseDir(token.NewFileSet(), pkgdir, nil, parser.PackageClauseOnly)
		if err != nil {
			log.Fatal(err) // 如果解析失败，则记录错误并退出
		}
		for name := range pkgs {
			if name == "main" {
				path := "./" + filepath.ToSlash(pkgdir) // 构造包路径
				commands = append(commands, path)
				break
			}
		}
	}
	return commands
}
