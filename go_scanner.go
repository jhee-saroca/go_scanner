// Code that is basically nmap
// run the code by typing this in CMD: 
// go run . -host scanme.nmap.org -end 32000 -workers 500


package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"time"
)

var services = map[int]string{
	21:   "ftp",
	22:   "ssh",
	23:   "telnet",
	25:   "smtp",
	53:   "dns",
	80:   "http",
	110:  "pop3",
	143:  "imap",
	443:  "https",
	445:  "smb",
	3306: "mysql",
	3389: "rdp",
	5432: "postgres",
	6379: "redis",
	8080: "http-alt",
}

// 
func scan(host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// creates workers for the goroutines
func worker(host string, ports <-chan int, results chan<- int, timeout time.Duration, wg *sync.WaitGroup) {
	defer wg.Done()
	for p := range ports {
		if scan(host, p, timeout) {
			results <- p
		}
	}
}

func main() {
	host := flag.String("host", "127.0.0.1", "target to scan")
	end := flag.Int("end", 1024, "scan ports 1 through this one")
	workers := flag.Int("workers", 100, "how many goroutines to run")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "how long to wait on each port")
	flag.Parse()

	if *end < 1 || *end > 65535 {
		fmt.Println("end port has to be between 1 and 65535")
		os.Exit(1)
	}

	if _, err := net.LookupHost(*host); err != nil {
		fmt.Println("couldn't resolve host:", *host)
		os.Exit(1)
	}

	fmt.Printf("scanning %s ports 1-%d with %d workers\n\n", *host, *end, *workers)
	began := time.Now()

	ports := make(chan int, *workers)
	results := make(chan int)
	var wg sync.WaitGroup

	// create workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go worker(*host, ports, results, *timeout, &wg)
	}

	go func() {
		for p := 1; p <= *end; p++ {
			ports <- p
		}
		close(ports)
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	var open []int
	for p := range results {
		open = append(open, p)
	}
	sort.Ints(open)

	if len(open) == 0 {
		fmt.Println("no open ports found")
	} else {
		fmt.Printf("%-10s %-7s %s\n", "PORT", "STATE", "SERVICE")
		for _, p := range open {
			name, ok := services[p]
			if !ok {
				name = "unknown"
			}
			fmt.Printf("%-10s %-7s %s\n", strconv.Itoa(p)+"/tcp", "open", name)
		}
	}

	fmt.Printf("\ndone in %s, %d open\n", time.Since(began).Round(time.Millisecond), len(open))
}