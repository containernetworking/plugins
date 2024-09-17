// Copyright 2020 CNI authors
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

package errors

import (
	"errors"
	"reflect"
	"testing"
)

func TestAnnotate(t *testing.T) {
	tests := []struct {
		name           string
		existingErr    error
		contextMessage string
		expectedErr    error
	}{
		{
			"nil error",
			nil,
			"context",
			nil,
		},
		{
			"normal case",
			errors.New("existing error"),
			"context",
			errors.New("context: existing error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(Annotate(test.existingErr, test.contextMessage), test.expectedErr) {
				t.Errorf("test case %s fails", test.name)
				return
			}
		})
	}
}

func TestAnnotatef(t *testing.T) {
	tests := []struct {
		name           string
		existingErr    error
		contextMessage string
		contextArgs    []interface{}
		expectedErr    error
	}{
		{
			"nil error",
			nil,
			"context",
			nil,
			nil,
		},
		{
			"normal case",
			errors.New("existing error"),
			"context",
			nil,
			errors.New("context: existing error"),
		},
		{
			"normal case with args",
			errors.New("existing error"),
			"context %s %d",
			[]interface{}{
				"arg",
				100,
			},
			errors.New("context arg 100: existing error"),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(Annotatef(test.existingErr, test.contextMessage, test.contextArgs...), test.expectedErr) {
				t.Errorf("test case %s fails", test.name)
				return
			}
		})
	}
}
