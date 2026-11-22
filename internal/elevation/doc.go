// internal/elevation/doc.go

// Package elevation answers what owatch asks about the privilege it runs
// with: whether the process is elevated, who the operator behind an elevated
// run is, and whether a directory can be changed by anyone other than the
// system, its administrators and that operator. A privileged process that
// writes where another user can plant or replace an entry does that user's
// work with its own privilege, so every part of owatch that writes or trusts a
// file judges the directory by this one copy of the rule.
package elevation
