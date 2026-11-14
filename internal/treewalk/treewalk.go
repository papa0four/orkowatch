// internal/treewalk/treewalk.go

// Package treewalk reads a directory tree with a bounded set of workers. A
// filesystem scan spends most of its time waiting on the operating system to
// list directories and answer per-entry queries, and several of those waits
// can overlap. The package owns the concurrency so its callers do not: a
// caller supplies what to do with one directory and what to do with each
// result, and neither needs a lock of its own.
package treewalk

import (
	"context"
	"sync"
)

type (
	// Dir is a directory waiting to be read. State is whatever its parent
	// decided its contents inherit, carried with the directory because
	// workers reach directories in no particular order and cannot rebuild
	// it from the path they took.
	Dir[S any] struct {
		Path  string
		State S
	}

	// Visit reads one directory. It returns the subdirectories to descend
	// into and what it found. Several visits run at once, so a Visit may
	// touch only its arguments, its own locals, and state that guards
	// itself; everything it wants kept goes in the result.
	Visit[S, R any] func(ctx context.Context, dir Dir[S]) (subdirs []Dir[S], result R)

	// queue hands directories to the workers. A worker that finds it empty
	// waits while any other worker is still reading, because that worker
	// may yet add subdirectories; once it is empty and nobody is reading,
	// the walk is over.
	queue[S any] struct {
		mu      sync.Mutex
		ready   *sync.Cond
		dirs    []Dir[S]
		reading int
	}
)

// Run walks the tree under root with the given number of workers and returns
// when every directory has been visited or ctx is done, in which case it
// returns ctx's error and the walk is incomplete.
//
// collect receives each visit's result. It is called by one goroutine at a
// time, so it may accumulate into ordinary variables. Results arrive in no
// particular order; a caller that needs a stable order sorts what it
// collected.
func Run[S, R any](ctx context.Context, workers int, root Dir[S], visit Visit[S, R], collect func(R)) error {
	q := &queue[S]{dirs: []Dir[S]{root}}
	q.ready = sync.NewCond(&q.mu)

	var collecting sync.Mutex
	var wg sync.WaitGroup
	for range max(workers, 1) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				dir, ok := q.take(ctx)
				if !ok {
					return
				}
				subdirs, result := visit(ctx, dir)

				collecting.Lock()
				collect(result)
				collecting.Unlock()

				q.done(subdirs)
			}
		}()
	}
	wg.Wait()

	return ctx.Err()
}

// take returns the next directory to read, waiting for one while other
// workers may still produce some. It reports false when the walk is over or
// ctx is done. A cancelled walk ends as soon as the visits in flight return:
// each of them wakes the waiters when it finishes.
func (q *queue[S]) take(ctx context.Context) (Dir[S], bool) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for len(q.dirs) == 0 && q.reading > 0 && ctx.Err() == nil {
		q.ready.Wait()
	}
	if len(q.dirs) == 0 || ctx.Err() != nil {
		// Wake the others so they see the same end and leave too.
		q.ready.Broadcast()
		return Dir[S]{}, false
	}

	last := len(q.dirs) - 1
	dir := q.dirs[last]
	q.dirs = q.dirs[:last]
	q.reading++
	return dir, true
}

// done records that a worker finished reading a directory and queues the
// subdirectories it found.
func (q *queue[S]) done(subdirs []Dir[S]) {
	q.mu.Lock()
	q.dirs = append(q.dirs, subdirs...)
	q.reading--
	q.mu.Unlock()
	q.ready.Broadcast()
}
