//go:build race

package server

// raceEnabled says that the tests run with the race detector, which distorts
// time measurements.
const raceEnabled = true
