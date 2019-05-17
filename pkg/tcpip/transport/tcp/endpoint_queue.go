// Copyright 2018 The gVisor Authors.
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

package tcp

import (
	"sync"
)

// endpointQueue is a bounded, thread-safe queue of TCP endpoints.
type endpointQueue struct {
	mu    sync.Mutex        `state:"nosave"`
	list  queueEndpointList `state:"wait"`
	limit int
	used  int
}

// empty determines if the queue is empty.
func (q *endpointQueue) empty() bool {
	q.mu.Lock()
	r := q.used == 0
	q.mu.Unlock()

	return r
}

// setLimit updates the limit. No endpoints are immediately dropped in case the
// queue becomes full due to the new limit.
func (q *endpointQueue) setLimit(limit int) {
	q.mu.Lock()
	q.limit = limit
	q.mu.Unlock()
}

// enqueue adds the given endpoint to the queue.
//
// Returns true when the endpoint is successfully added to the queue. Returns
// false if the queue is full.
func (q *endpointQueue) enqueue(s *queueEndpoint) bool {
	q.mu.Lock()
	r := q.used < q.limit
	if r {
		q.list.PushBack(s)
		q.used++
	}
	q.mu.Unlock()

	return r
}

// dequeue removes and returns the next queueEndpoint from queue, if one
// exists.
func (q *endpointQueue) dequeue() *queueEndpoint {
	q.mu.Lock()
	s := q.list.Front()
	if s != nil {
		q.list.Remove(s)
		q.used--
	}
	q.mu.Unlock()

	return s
}
