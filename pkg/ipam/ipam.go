// Copyright 2015 CNI authors
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

package ipam

import (
	"context"
	"time"

	"github.com/containernetworking/cni/pkg/invoke"
	"github.com/containernetworking/cni/pkg/types"
)

const (
	delegateTimeout = 30 * time.Second
)

// ExecAdd delegates ADD action of CNI plugin
func ExecAdd(plugin string, netconf []byte) (types.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), delegateTimeout)
	defer cancel()

	return ExecAddWithContext(ctx, plugin, netconf)
}

// ExecCheck delegates CHECK action of CNI plugin
func ExecCheck(plugin string, netconf []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), delegateTimeout)
	defer cancel()

	return ExecCheckWithContext(ctx, plugin, netconf)
}

// ExecDel delegates DEL action of CNI plugin
func ExecDel(plugin string, netconf []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), delegateTimeout)
	defer cancel()

	return ExecDelWithContext(ctx, plugin, netconf)
}

// ExecAddWithContext delegates ADD action of CNI plugin with context
func ExecAddWithContext(ctx context.Context, plugin string, netconf []byte) (types.Result, error) {
	return invoke.DelegateAdd(ctx, plugin, netconf, nil)
}

// ExecCheckWithContext delegates CHECK action of CNI plugin with context
func ExecCheckWithContext(ctx context.Context, plugin string, netconf []byte) error {
	return invoke.DelegateCheck(ctx, plugin, netconf, nil)
}

// ExecDelWithContext delegates DEL action of CNI plugin with context
func ExecDelWithContext(ctx context.Context, plugin string, netconf []byte) error {
	return invoke.DelegateDel(ctx, plugin, netconf, nil)
}
