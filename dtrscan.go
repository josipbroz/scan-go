package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"gopkg.in/yaml.v2"
)

const (
	ApiCall     = "api/v0/repositories"
	PageSize    = "1000000"
	defaultDays = 10000
	ScanUnknown = 0
	ScanPending = 5
	ScanOk      = 6
	Usage       = `	
Usage: dtrscan --user [DTR user] --token [DTR access token] [OPTION]

Options:
  -h --help     Show this help
  --file        Namespaces file (defaults to namespaces.yaml)
  --url         DTR URL (defaults to dtr.company.com)
  --days        Force scan if scan is older than 'days'
  --no_dry_run  Start scans
`
)

// To Do
// Add a function to check access to DTR and fail if not authenticated
// Make functions return an error instead of terminating
// Tests
func main() {
	var (
		userId   = flag.String("user", "", "DTR User id")
		token    = flag.String("token", "", "DTR Access Token")
		url      = flag.String("url", "https://dtr.company.com", "DTR URL")
		nameFile = flag.String("file", "namespaces.yaml", "Namespaces file")
		days     = flag.Int("days", defaultDays, "Force scan if older than days")
		noDryRun = flag.Bool("no_dry_run", false, "Start scans")
	)
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), Usage)
	}
	flag.Parse()

	log.SetFlags(log.LstdFlags)

	if *userId == "" || *token == "" {
		fmt.Fprint(flag.CommandLine.Output(), Usage)
		os.Exit(0)
	}
	log.Printf("user %v file %v url %v\n", *userId, *nameFile, *url)

	if *days <= 0 || *days > defaultDays {
		log.Printf("Invalid number of days entered, must be between 1 and %v. Setting days to %v", defaultDays, defaultDays)
		*days = defaultDays
	}

	// If --no_dry_run is not set dry_run evaulate to True and no
	// scans will be started. Otherwise, if --no_dry_run is present dry_run
	// is false and scans will run
	// Specify no_dry_run to start scans otherwise no tags will be scanned (a 'dry run')
	dryRun := !*noDryRun

	var cfg = Config{
		UserId: *userId,
		Token:  *token,
		Url:    *url,
		Days:   *days,
		dryRun: dryRun,
		Today:  time.Now().UTC()}

	// If there are no tags for a namespace/name combination it will be ignored
	ns, nserr := getNamespaces(*nameFile)
	if nserr != nil {
		log.Fatalf("Error getting namespaces %v\n", nserr)
	}
	var nameCount int16
	var tagCount int16
	for _, namespace := range ns.Namespaces {
		names := getNames(namespace, cfg)
		for _, name := range names.Repository {
			nameCount++
			tags := getTags(namespace, name.Name, cfg)
			for _, tag := range *tags {
				tagDetail := getTagDetail(namespace, name.Name, tag.Name, cfg)
				for _, tagRecord := range *tagDetail {
					tagCount++
					tagRecord.InspectandScanTag(namespace, name.Name, cfg)
				}
			}
		}
	}
	log.Printf("Reviewed %-4v repositories and %-4v tags. If a repository has no tags it will not be shown in the output",
		nameCount, tagCount)
}

type Config struct {
	UserId string
	Token  string
	Url    string
	Days   int
	dryRun bool
	Today  time.Time
}

type Namespaces struct {
	Namespaces []string `yaml:"Namespaces"`
}

type Names struct {
	Name string `json:"name"`
}

type Repositories struct {
	Repository []Names `json:"repositories"`
}

type Tags struct {
	Name string
}

type Manifest struct {
	Os           string `json:"os"`
	Architecture string `json:"architecture"`
}

type VulnSummary struct {
	Critical         int       `json:"critical"`
	Major            int       `json:"major"`
	Minor            int       `json:"minor"`
	LastScanStatus   int       `json:"last_scan_status"`
	CheckCompletedAt time.Time `json:"check_completed_at"`
	ShouldRescan     bool      `json:"should_rescan"`
}

type TagDetail struct {
	Name        string      `json:"name"`
	UpdatedAt   time.Time   `json:"updatedAt"`
	CreatedAt   time.Time   `json:"createdAt"`
	Manifest    Manifest    `json:"manifest"`
	VulnSummary VulnSummary `json:"vuln_summary"`
}

func getNamespaces(fileName string) (*Namespaces, error) {
	yamlFile, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}
	var ns Namespaces
	err = yaml.Unmarshal(yamlFile, &ns)
	if err != nil {
		return nil, err
	}
	return &ns, nil
}

func getNames(ns string, c Config) *Repositories {
	// Call {url}/api/v0/repositories/{ns}/?pageSize=1000000
	// If PageSize is not set at most 10 results will be returned by default
	rp := new(Repositories)
	endPoint := fmt.Sprintf("%s/%s/%s", c.Url, ApiCall, ns+"/?pageSize="+PageSize)

	client := &http.Client{Timeout: 90 * time.Second}
	req, err := http.NewRequest("GET", endPoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.UserId, c.Token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	// ReadAll returns []byte
	repos, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	err3 := json.Unmarshal(repos, &rp)
	if err3 != nil {
		log.Fatal(err3)
	}
	return rp
}

func getTags(ns string, name string, c Config) *[]Tags {
	// Call {url}/api/v0/repositories/{ns}/{name}/tags
	var dtrTags []Tags

	endPoint := fmt.Sprintf("%s/%s/%s/%s/tags", c.Url, ApiCall, ns, name)

	client := &http.Client{Timeout: 90 * time.Second}
	req, err := http.NewRequest("GET", endPoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.UserId, c.Token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	repos, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	err3 := json.Unmarshal(repos, &dtrTags)
	if err3 != nil {
		log.Fatal(err3)
	}
	return &dtrTags
}

func getTagDetail(ns string, name string, tag string, c Config) *[]TagDetail {
	// Call {url}/api/v0/repositories/{ns}/{name}/tags/{reference} where reference is the tag name
	var tagDetail []TagDetail

	endPoint := fmt.Sprintf("%s/%s/%s/%s/tags/%s", c.Url, ApiCall, ns, name, tag)

	client := &http.Client{Timeout: 900 * time.Second}
	req, err := http.NewRequest("GET", endPoint, nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.UserId, c.Token)

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	repos, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		log.Fatal(err)
	}
	err3 := json.Unmarshal(repos, &tagDetail)
	if err3 != nil {
		log.Fatal(err3)
	}
	return &tagDetail
}

func (t *TagDetail) InspectandScanTag(ns string, name string, c Config) {
	// {url}/api/v0/imagescan/scan/{ns}/{name}/{reference}/{os}/{arch}
	endPoint := fmt.Sprintf("%s/api/v0/imagescan/scan/%s/%s/%s/%s/%s",
		c.Url,
		ns,
		name,
		t.Name,
		t.Manifest.Os,
		t.Manifest.Architecture)

	client := &http.Client{Timeout: 900 * time.Second}
	req, err := http.NewRequest("POST", endPoint, nil)
	if err != nil {
		log.Printf("Could not create POST request %v\n", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.UserId, c.Token)

	now := c.Today
	daysSince, _, _, _ := getDifference(t.VulnSummary.CheckCompletedAt, now)

	if t.VulnSummary.LastScanStatus == ScanPending {
		log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v",
			"Scan is pending for",
			ns,
			name,
			t.Name,
			t.VulnSummary.LastScanStatus,
			t.VulnSummary.ShouldRescan,
			t.VulnSummary.CheckCompletedAt)
	} else if daysSince > c.Days {
		if c.dryRun {
			log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v %v days ago",
				"Will scan if no_dry_run",
				ns,
				name,
				t.Name,
				t.VulnSummary.LastScanStatus,
				t.VulnSummary.ShouldRescan,
				t.VulnSummary.CheckCompletedAt,
				daysSince)
		} else {
			log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v %v days ago",
				"Sending request to scan",
				ns,
				name,
				t.Name,
				t.VulnSummary.LastScanStatus,
				t.VulnSummary.ShouldRescan,
				t.VulnSummary.CheckCompletedAt,
				daysSince)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Unable to scan %v, %v\n", t.Name, err)
			}
			resp.Body.Close()
		}
	} else if !t.VulnSummary.ShouldRescan && t.VulnSummary.LastScanStatus == ScanOk {
		log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v",
			"Scan is up-to-date for",
			ns,
			name,
			t.Name,
			t.VulnSummary.LastScanStatus,
			t.VulnSummary.ShouldRescan,
			t.VulnSummary.CheckCompletedAt)
	} else if t.VulnSummary.ShouldRescan || (t.VulnSummary.LastScanStatus == ScanUnknown && !t.VulnSummary.ShouldRescan) {
		if c.dryRun {
			log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v %v days ago",
				"Will scan if no_dry_run",
				ns,
				name,
				t.Name,
				t.VulnSummary.LastScanStatus,
				t.VulnSummary.ShouldRescan,
				t.VulnSummary.CheckCompletedAt,
				daysSince)
		} else {
			log.Printf("%-27v %-16v %-45v %-45v %-1v %-5v %-40v %v days ago",
				"Sending request to scan",
				ns,
				name,
				t.Name,
				t.VulnSummary.LastScanStatus,
				t.VulnSummary.ShouldRescan,
				t.VulnSummary.CheckCompletedAt,
				daysSince)
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Unable to scan %v, %v\n", t.Name, err)
			}
			resp.Body.Close()
		}
	} else {
		log.Printf("%-27v %-16v %-45v %-45v",
			"Scan status is unknown for",
			ns,
			name,
			t.Name)
	}
}

// leapYears and getDifference are
// from https://www.geeksforgeeks.org/calculating-total-number-of-hours-days-minutes-and-seconds-between-two-dates-in-golang/
func leapYears(date time.Time) (leaps int) {
	// Returns the year, month, date of a time object
	y, m, _ := date.Date()

	if m <= 2 {
		y--
	}
	leaps = y/4 + y/400 - y/100
	return leaps
}

func getDifference(a, b time.Time) (days, hours, minutes, seconds int) {
	// Calculates the  difference between two dates and times
	// and returns the days, hours, minutes, seconds

	// month-wise days
	monthDays := [12]int{31, 28, 31, 30, 31,
		30, 31, 31, 30, 31, 30, 31}

	// extracting years, months,
	// days of two dates
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()

	// extracting hours, minutes,
	// seconds of two times
	h1, min1, s1 := a.Clock()
	h2, min2, s2 := b.Clock()

	// totalDays since the
	// beginning = year*365 + number_of_days
	totalDays1 := y1*365 + d1

	// adding days of the months
	// before the current month
	for i := 0; i < (int)(m1)-1; i++ {
		totalDays1 += monthDays[i]
	}

	// counting leap years since
	// beginning to the year "a"
	// and adding that many extra
	// days to the totaldays
	totalDays1 += leapYears(a)

	// Similar procedure for second date
	totalDays2 := y2*365 + d2

	for i := 0; i < (int)(m2)-1; i++ {
		totalDays2 += monthDays[i]
	}

	totalDays2 += leapYears(b)

	days = totalDays2 - totalDays1

	// calculating hour, minutes,
	// seconds differences
	hours = h2 - h1
	minutes = min2 - min1
	seconds = s2 - s1

	// if seconds difference goes below 0,
	// add 60 and decrement number of minutes
	if seconds < 0 {
		seconds += 60
		minutes--
	}

	// performing similar operations
	// on minutes and hours
	if minutes < 0 {
		minutes += 60
		hours--
	}

	// performing similar operations
	// on hours and days
	if hours < 0 {
		hours += 24
		days--
	}

	return days, hours, minutes, seconds
}
