// Copyright 2026 CNI authors
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

package disk

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func populateSyntheticLeases(dir string, count int) error {
	for i := 0; i < count; i++ {
		b2 := (i >> 8) & 0xFF
		b3 := i & 0xFF
		ipStr := fmt.Sprintf("10.244.%d.%d", b2, b3)
		filePath := filepath.Join(dir, ipStr)
		content := fmt.Sprintf("container-%05d\r\neth0\r\n", i)
		if err := os.WriteFile(filePath, []byte(content), 0o644); err != nil {
			return err
		}
	}
	return nil
}

// BenchmarkStoreGetByIDScaling benchmarks GetByID duration across directory sizes.
func BenchmarkStoreGetByIDScaling(b *testing.B) {
	sizes := []int{100, 1000, 5000}

	for _, size := range sizes {
		b.Run(fmt.Sprintf("PoolSize-%d", size), func(b *testing.B) {
			tempDir, err := os.MkdirTemp("", "hostlocal_bench_*")
			if err != nil {
				b.Fatalf("failed to create tempDir: %v", err)
			}
			defer os.RemoveAll(tempDir)

			if err := populateSyntheticLeases(tempDir, size); err != nil {
				b.Fatalf("failed to populate leases: %v", err)
			}

			store := &Store{dataDir: tempDir}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = store.GetByID("target-container", "eth0")
			}
		})
	}
}
