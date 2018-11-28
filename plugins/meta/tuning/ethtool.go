// Copyright 2016 CNI authors
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

package main

import (
	"fmt"
)

type offloadFunc func(string) error

var offloadEnableFuncs map[string]offloadFunc = map[string]offloadFunc{
	"tx":  EthtoolTxCheckSumOn,
	"tso": EthtoolTsoOn,
	"gso": EthtoolGsoOn,
}

var offloadDisableFuncs map[string]offloadFunc = map[string]offloadFunc{
	"tx":  EthtoolTxCheckSumOff,
	"tso": EthtoolTsoOff,
	"gso": EthtoolGsoOff,
}

func changeEthtool(conf *EthtoolConf) error {
	for feature, enable := range conf.Offloads {
		if enable {
			if f, ok := offloadEnableFuncs[feature]; ok {
				if err := f(conf.IfName); err != nil {
					return fmt.Errorf("Failed to enable offload feature %s: %v", feature, err)
				}
			} else {
				return fmt.Errorf("Offload feature %s is not supported", feature)
			}
		} else {
			if f, ok := offloadDisableFuncs[feature]; ok {
				if err := f(conf.IfName); err != nil {
					return fmt.Errorf("Failed to disable offload feature %s: %v", feature, err)
				}
			} else {
				return fmt.Errorf("Offload feature %s is not supported", feature)
			}
		}
	}
	return nil
}
