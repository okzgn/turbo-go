//go:build race

package main

// raceEnabled says that the tests run with the race detector, which distorts
// time measurements.
const raceEnabled = true
