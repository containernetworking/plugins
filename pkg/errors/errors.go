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

import "fmt"

// Annotate is used to add extra context to an existing error. The return will be
// a new error which carries error message from both context message and existing error.
func Annotate(err error, message string) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %v", message, err)
}

// Annotatef is used to add extra context with args to an existing error. The return will be
// a new error which carries error message from both context message and existing error.
func Annotatef(err error, message string, args ...interface{}) error {
	if err == nil {
		return nil
	}

	return fmt.Errorf("%s: %v", fmt.Sprintf(message, args...), err)
}
