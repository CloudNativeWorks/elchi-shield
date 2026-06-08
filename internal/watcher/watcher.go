package watcher

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/cloudnativeworks/elchi-shield/internal/logging"
)

// Watcher observes a directory and invokes a callback after a debounce window
// once filesystem activity settles. Bursts of events (common when an agent
// rewrites several files) coalesce into a single callback, so the expensive
// reload pipeline runs once per settled change rather than once per inotify
// event.
type Watcher struct {
	dir      string
	debounce time.Duration
	onChange func()
	log      *slog.Logger
}

// New creates a Watcher for dir. debounce is the quiet period after the last
// event before onChange fires (e.g. 300ms). onChange must be non-nil and is
// invoked from the Watcher's goroutine, one call at a time.
func New(dir string, debounce time.Duration, onChange func(), log *slog.Logger) (*Watcher, error) {
	if onChange == nil {
		return nil, errors.New("watcher: onChange callback is required")
	}
	if debounce <= 0 {
		debounce = 300 * time.Millisecond
	}
	return &Watcher{dir: dir, debounce: debounce, onChange: onChange, log: log}, nil
}

// Run starts watching and blocks until ctx is cancelled. It returns ctx.Err()
// on shutdown, or a setup error if the directory cannot be watched.
func (w *Watcher) Run(ctx context.Context) error {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("watcher: create: %w", err)
	}
	defer func() { _ = fsw.Close() }()

	// The config directory may not exist yet at startup (e.g. elchi-client has not
	// written it, or a k8s volume is still mounting). Wait for it instead of
	// hard-failing so the service comes up and self-heals.
	waited, err := w.ensureWatch(ctx, fsw)
	if err != nil {
		return err
	}
	if w.log != nil {
		w.log.Info("config watcher started", "dir", w.dir, "debounce", w.debounce)
	}

	// A stopped timer that we (re)set on each relevant event. Its channel fires
	// once the directory has been quiet for the debounce window.
	timer := time.NewTimer(w.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	pending := false

	// If we had to wait for the directory, files may have been written before the
	// watch was established (those creates produce no event). Schedule an initial
	// reload so the current contents are picked up.
	if waited {
		pending = true
		timer.Reset(w.debounce)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case ev, ok := <-fsw.Events:
			if !ok {
				return nil
			}
			if !w.relevant(ev) {
				continue
			}
			// If the watched directory itself was removed or replaced (k8s
			// ConfigMap volumes swap the directory atomically), the kernel watch is
			// now stale. Re-establish it (waiting for the dir to reappear) so we keep
			// seeing changes; then fall through to schedule a reload.
			if ev.Name == w.dir && ev.Op&(fsnotify.Remove|fsnotify.Rename) != 0 {
				if _, err := w.ensureWatch(ctx, fsw); err != nil {
					return err
				}
			}
			if !pending {
				pending = true
			} else if !timer.Stop() {
				// Drain a fired-but-unread timer before resetting.
				select {
				case <-timer.C:
				default:
				}
			}
			timer.Reset(w.debounce)

		case <-timer.C:
			if pending {
				pending = false
				w.onChange()
			}

		case err, ok := <-fsw.Errors:
			if !ok {
				return nil
			}
			if w.log != nil {
				w.log.Warn("config watcher error", logging.Err(err))
			}
		}
	}
}

// relevant filters out events that cannot change the effective config set. We
// react to create/write/rename/remove; chmod-only events are ignored.
func (w *Watcher) relevant(ev fsnotify.Event) bool {
	return ev.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) != 0
}

// ensureWatch (re)adds the directory to the kernel watch, first waiting for the
// directory to exist. It is used at startup (the dir may not be created yet) and
// after the directory is removed/replaced (the prior watch went stale). It
// returns whether it had to wait for the directory (so the caller can schedule a
// catch-up reload for files written before the watch was added) and ctx.Err() if
// cancelled while waiting. fsnotify.Add is idempotent, so re-adding an
// already-watched directory is harmless.
func (w *Watcher) ensureWatch(ctx context.Context, fsw *fsnotify.Watcher) (waited bool, err error) {
	const pollInterval = 500 * time.Millisecond
	for {
		if fi, statErr := os.Stat(w.dir); statErr == nil && fi.IsDir() {
			if addErr := fsw.Add(w.dir); addErr == nil {
				return waited, nil
			} else if w.log != nil {
				w.log.Warn("config watcher: add failed, retrying", "dir", w.dir, logging.Err(addErr))
			}
		} else if !waited && w.log != nil {
			w.log.Warn("config watcher: directory not present yet, waiting", "dir", w.dir)
		}
		waited = true
		select {
		case <-ctx.Done():
			return waited, ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}
