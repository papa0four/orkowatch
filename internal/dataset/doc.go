// internal/dataset/doc.go

// Package dataset states what owatch knows about a vulnerability dataset held
// on the host: what a source says about each of its datasets, the manifest
// kept beside the data, and how old the data is. A source is added as a type
// that satisfies Dataset; the store and the commands read every source
// through that interface and name none of them.
//
// Everything a dataset carries is untrusted input, whoever fetched it and
// however it reached the host, so a manifest is bounded in size, refused when
// it holds anything it should not, and judged against the dataset it claims
// to be before anything it says is used.
package dataset
