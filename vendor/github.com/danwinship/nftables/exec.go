/*
Copyright 2023 Red Hat, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package nftables

import (
	"fmt"
	"io"
	"os/exec"
	"reflect"
	"testing"
)

// execer is a mockable wrapper around os/exec.
type execer interface {
	// LookPath wraps exec.LookPath
	LookPath(file string) (string, error)

	// Run runs cmd as with cmd.Output(). If an error occurs, and the process outputs
	// stderr, then that output will be returned in the error.
	Run(cmd *exec.Cmd) (string, error)
}

// realExec implements execer by actually using os/exec
type realExec struct{}

// LookPath is part of execer
func (_ realExec) LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// Run is part of execer
func (_ realExec) Run(cmd *exec.Cmd) (string, error) {
	out, err := cmd.Output()
	if err != nil {
		err = wrapError(err)
	}
	return string(out), err
}

// fakeExec is a mockable implementation of execer for unit tests
type fakeExec struct {
	t *testing.T

	// missingBinaries is the set of binaries for which LookPath should fail
	missingBinaries map[string]bool

	// expected is the list of expected Run calls
	expected []expectedCmd

	// matched is used internally, to keep track of where we are in expected
	matched int
}

func newFakeExec(t *testing.T) *fakeExec {
	return &fakeExec{t: t, missingBinaries: make(map[string]bool)}
}

func (fe *fakeExec) LookPath(file string) (string, error) {
	if fe.missingBinaries[file] {
		return "", &exec.Error{file, exec.ErrNotFound}
	}
	return "/" + file, nil
}

// expectedCmd details one expected fakeExec Cmd
type expectedCmd struct {
	args   []string
	stdin  string
	stdout string
	err    error
}

func (fe *fakeExec) Run(cmd *exec.Cmd) (string, error) {
	if fe.t.Failed() {
		return "", fmt.Errorf("unit test failed")
	}

	if len(fe.expected) == fe.matched {
		fe.t.Errorf("ran out of commands before executing %v", cmd.Args)
		return "", fmt.Errorf("unit test failed")
	}
	expected := &fe.expected[fe.matched]
	fe.matched++

	if !reflect.DeepEqual(expected.args, cmd.Args) {
		fe.t.Errorf("incorrect arguments: expected %v, got %v", expected.args, cmd.Args)
		return "", fmt.Errorf("unit test failed")
	}

	var stdin string
	if cmd.Stdin != nil {
		inBytes, _ := io.ReadAll(cmd.Stdin)
		stdin = string(inBytes)
	}
	if expected.stdin != stdin {
		fe.t.Errorf("incorrect stdin: expected %q, got %q", expected.stdin, stdin)
		return "", fmt.Errorf("unit test failed")
	}

	return expected.stdout, expected.err
}
