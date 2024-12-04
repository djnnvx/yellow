package scan

import (
	"fmt"
)

type RobotsTxt struct {
}

func (d *RobotsTxt) Info(url string) {
	fmt.Println("[+] Running RobotsTxt on", url)
}

func (d *RobotsTxt) Configure(c interface{}) {
}

func (d *RobotsTxt) Run(url string) {

	fmt.Printf("[SCAN %s] RobotsTxt scan for %s completed\n\n", url)
}
