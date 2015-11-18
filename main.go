package main

// TODO
//    * Add https support for clair API requests
//    * Add local directory support

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
)

var (
	clair        ClairAPI
	openvzMirror string
)

type ClairAPI struct {
	Address         string `json:"adress"`
	Port            int    `json:"port"`
	HttpsEnable     bool   `json:"https_enable"`
	MinimumPriority string
}

type AddLayoutRequestAPI struct {
	ID       string `json:"ID"`
	Path     string `json:"Path"`
	ParantID string `json:"ParantID"`
}

type VulnerabilityItem struct {
	ID          string `json:"ID"`
	Link        string `json:"Link"`
	Priority    string `json:"Priority"`
	Description string `json:"Description"`
}

type GetLayersVulnResponseAPI struct {
	Vulnerabilities []VulnerabilityItem `json:"Vulnerabilities"`
}

func init() {
	// Add logging
	log.SetOutput(os.Stdout)
	log.SetPrefix("main: ")
	log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)

	openvzMirrorFlag := flag.String("m", "https://download.openvz.org/template/precreated/", "Adress to link(directory - not supported yet) with precreated templates")
	clairAddressFlag := flag.String("a", "127.0.0.1", "Adress to clair API")
	clairPortFlag := flag.Int("p", 6060, "Adress to clair API")
	clairMinPriorityFlag := flag.String("P", "High", "The minimum priority of the returned vulnerabilities")

	flag.Parse()
	openvzMirror = *openvzMirrorFlag
	clair.Address = *clairAddressFlag
	clair.Port = *clairPortFlag
	// TODO - check priority
	clair.MinimumPriority = *clairMinPriorityFlag
}

func main() {
	fmt.Println("We use:")
	fmt.Println("Clair - ", clair.Address+":"+strconv.Itoa(clair.Port))
	fmt.Println("OpenVZ mirror - ", openvzMirror)

	templateList, err := GetRemoteListing(openvzMirror)
	if err != nil {
		log.Fatal("Cannot get template listing - exit")
	}
	templateList = CleanZeroValuesFromArray(templateList)
	fmt.Println("We have", len(templateList), "templates on mirror")
	fmt.Println()

	supportTemplates := regexp.MustCompile(`(?i)(ubuntu|debian|centos)`)

	for _, template := range templateList {

		if !supportTemplates.MatchString(template) {
			log.Println("\"" + template + "\" not supported OS - continue")
			continue
		}
		fmt.Println("Try to add ", template)
		err = clair.AddLayer(openvzMirror, template)
		if err != nil {
			log.Println("Error - cannot add template", template)
		} else {
			fmt.Println(template, "added success")
			fmt.Println("You can check it via:")
			fmt.Println("curl -s http://" + clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers/" + template + "/vulnerabilities?minimumPriority=" + clair.MinimumPriority + " | python -m json.tool")
			vulnList, err := clair.GetLayerVuln(template)
			if err != nil {
				fmt.Println("Cannot get vulnerabilities for this template - see errors and check it manual, please")
			} else {
				fmt.Println("Detect", len(vulnList), "vulnerabilities for this template")
			}
			fmt.Println()
		}
	}

}

func GetRemoteListing(adress string) (templateList []string, err error) {
	result, err := http.Get(adress + "/.listing")
	if err != nil {
		log.Println("Cannot get listing via web from ", adress)
		log.Println(err)
		return
	}
	listingAnswerByte, err := ioutil.ReadAll(result.Body)
	defer result.Body.Close()
	if err != nil {
		log.Println("Cannot get body from http responce with error ", err)
		return
	}

	templateList = strings.Split(string(listingAnswerByte), "\n")
	return
}

func CleanZeroValuesFromArray(array []string) []string {
	var cleanArray []string
	for _, value := range array {
		if len(value) > 0 {
			cleanArray = append(cleanArray, value)
		}
	}
	return cleanArray
}

// https://github.com/coreos/clair/blob/master/docs/API.md#insert-a-new-layer
func (clair ClairAPI) AddLayer(openvzMirror string, templateName string) error {
	url := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers"
	if clair.HttpsEnable {
		// TODO
	} else {
		url = "http://" + url
	}

	jsonRequest, err := json.Marshal(AddLayoutRequestAPI{ID: templateName, Path: openvzMirror + "/" + templateName + ".tar.gz"})
	if err != nil {
		log.Println("Cannot convert to json request with error: ", err)
		return err
	}

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonRequest))
	if err != nil {
		log.Println("Cannot generate request: ", err)
		return err
	}
	request.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	response, err := client.Do(request)
	if err != nil {
		log.Println("Send request failed request: ", err)
		return err
	}

	// if OK  - returned "201 Created"
	if response.StatusCode != 201 {
		defer response.Body.Close()
		body, _ := ioutil.ReadAll(response.Body)
		log.Println("Error - response not ok - ", response.Status, " with message: ", string(body))
		return errors.New(string(body))
	}

	return nil
}

// https://github.com/coreos/clair/blob/master/docs/API.md#get-a-layers-vulnerabilities
func (clair ClairAPI) GetLayerVuln(templateName string) (vulnList []VulnerabilityItem, err error) {
	url := clair.Address + ":" + strconv.Itoa(clair.Port) + "/v1/layers/" + templateName + "/vulnerabilities" + "?minimumPriority=" + clair.MinimumPriority
	if clair.HttpsEnable {
		// TODO
	} else {
		url = "http://" + url
	}

	response, err := http.Get(url)
	if err != nil {
		log.Println("Send request failed request: ", err)
		return vulnList, err
	}
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)

	// if OK  - returned "200 OK"
	if response.StatusCode != 200 {
		log.Println("Error - response not ok - ", response.Status, " with message: ", string(body))
		return vulnList, errors.New(string(body))
	}

	var result GetLayersVulnResponseAPI
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Println("Cannot parse answer from clair to json: ", err)
		return vulnList, err
	}
	vulnList = result.Vulnerabilities
	return vulnList, nil
}
