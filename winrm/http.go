package winrm

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/masterzen/winrm/soap"
)

var soapXML string = "application/soap+xml"

type HttpPost func(*Client, *soap.SoapMessage) (string, error)

func body(response *http.Response) (content string, err error) {
	contentType := response.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, soapXML) {
		var body []byte
		body, err = ioutil.ReadAll(response.Body)
		if err != nil {
			err = fmt.Errorf("error while reading request body %s", err)
			return
		}

		content = string(body)
		return
	} else {
		err = fmt.Errorf("invalid content-type: %s", contentType)
		return
	}
	return
}

func Http_post(client *Client, request *soap.SoapMessage) (response string, err error) {
	httpClient := &http.Client{Transport: client.transport}

	req, err := http.NewRequest("POST", client.url, strings.NewReader(request.String()))
	if err != nil {
		err = fmt.Errorf("impossible to create http request %s", err)
		return
	}
	req.Header.Set("Content-Type", soapXML+";charset=UTF-8")
	req.SetBasicAuth(client.username, client.password)
	req.Close = true
	resp, err := httpClient.Do(req)
	if err != nil {
		err = fmt.Errorf("error while sending request to endpoint %s", err)
		return
	}
	defer resp.Body.Close()

	response, err = body(resp)
	if resp.StatusCode != 200 && err == nil {
		err = fmt.Errorf("http error: %d - %s", resp.StatusCode, body)
	}

	return
}
