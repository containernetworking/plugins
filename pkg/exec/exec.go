// Copyright 2017 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package exec

import (
	"io"
	osexec "os/exec"
)

type cmdWrapper osexec.Cmd

var _ Cmd = &cmdWrapper{}

type Cmd interface {
	Run() error
	SetStderr(io.Writer)
	SetStdout(io.Writer)
	SetStdin(io.Reader)
}

type Interface interface {
	Command(cmd string, args ...string) Cmd
	LookPath(file string) (string, error)
}

type executor struct{}

func New() Interface {
	return &executor{}
}

func (executor *executor) Command(cmd string, args ...string) Cmd {
	return (*cmdWrapper)(osexec.Command(cmd, args...))
}

func (executor *executor) LookPath(file string) (string, error) {
	return osexec.LookPath(file)
}

func (cmd *cmdWrapper) Run() error {
	return (*osexec.Cmd)(cmd).Run()
}

func (cmd *cmdWrapper) SetStdin(in io.Reader) {
	cmd.Stdin = in
}

func (cmd *cmdWrapper) SetStdout(out io.Writer) {
	cmd.Stdout = out
}

func (cmd *cmdWrapper) SetStderr(out io.Writer) {
	cmd.Stderr = out
}
