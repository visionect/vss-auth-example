package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"strings"
	"time"
)

var (
	ErrMissingCredentials = errors.New("missing credentials")
)

type vssClient struct {
	address   string
	apiKey    string
	apiSecret string
}

type vssSession struct {
	UUID    string `json:"Uuid"`
	Backend struct {
		Name   string
		Fields map[string]string
	}
	Options map[string]string
}

type okularStatus struct {
	AvgLoad      float64
	StdDeviation float64
	NumCPU       int
	Sessions     int
	MaxSessions  int
	Host         string
}

type vssStatus struct {
	Version string
	Okulars map[string]okularStatus
}

var quoteEscaper = strings.NewReplacer("\\", "\\\\", `"`, "\\\"")

func escapeQuotes(s string) string {

	return quoteEscaper.Replace(s)

}

func createHtmlMultipart(b []byte) (io.Reader, string, error) {
	buf := bytes.NewReader(b)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, err := w.CreateFormFile("file", "app.tar")
	if err != nil {
		return nil, "", err
	}
	//w.WriteField("name", "image_0")
	io.Copy(part, buf)
	w.Close()
	return body, w.FormDataContentType(), nil
}
func createHttpMultipart(b []byte) (io.Reader, string, error) {
	buf := bytes.NewReader(b)
	body := &bytes.Buffer{}
	w := multipart.NewWriter(body)
	part, err := w.CreateFormFile("image", "image.png")
	if err != nil {
		return nil, "", err
	}
	io.Copy(part, buf)
	w.Close()
	return body, w.FormDataContentType(), nil
}

// example call: Call("/api/user/", "GET", body)
func (c *vssClient) call(name, method string, requestBody ...[]byte) ([]byte, error) {
	var err error
	contentType := "application/json"
	var bodyReader io.Reader
	multiPart := false
	if method == "PUT-MULTIPART" {
		multiPart = true
		method = method[:3]
	} else if method == "POST-MULTIPART" {
		multiPart = true
		method = method[:4]
	}

	if c.apiKey == "" || c.apiSecret == "" {
		return nil, ErrMissingCredentials
	}

	client := &http.Client{}

	url := c.address //"http://%s:8081", c.address)

	if strings.HasPrefix(url, "https") {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client = &http.Client{
			Transport: tr,
			Timeout:   30 * time.Second,
		}
	}

	if len(requestBody) > 0 {
		if multiPart {
			if method == "PUT" {
				bodyReader, contentType, err = createHttpMultipart(requestBody[0])
			} else if method == "POST" {
				bodyReader, contentType, err = createHtmlMultipart(requestBody[0])
			}
			if err != nil {
				return nil, err
			}
		} else {
			bodyReader = bytes.NewBuffer(requestBody[0])
		}
	}

	req, err := http.NewRequest(method, fmt.Sprintf("%s%s", url, name), bodyReader)
	date := time.Now().Format(time.RFC1123)
	headerData := fmt.Sprintf("%s\n\n%s\n%s\n%s", method, contentType, date, name)

	h := hmac.New(sha256.New, []byte(c.apiSecret))
	h.Write([]byte(headerData))
	req.Header.Add("Content-Type", contentType)
	req.Header.Add("Date", date)
	req.Header.Add("Authorization", c.apiKey+":"+base64.StdEncoding.EncodeToString(h.Sum(nil)))

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if strings.Contains(string(body), "Login") {
		return nil, ErrMissingCredentials
	}
	if strings.HasPrefix(string(body), "404") {
		return nil, errors.New("not found")
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (c *vssClient) putSession(id string, session *vssSession) error {
	b, err := json.Marshal(&session)
	if err != nil {
		return err
	}
	_, err = c.call(fmt.Sprintf("/api/session/%s", id), "PUT", b)
	if err != nil {
		return err
	}
	return nil
}

func (c *vssClient) restartSessions(sessions []string) error {
	out, _ := json.Marshal(sessions)
	_, err := c.call("/api/session/restart", "POST", out)
	if err != nil {
		return err
	}
	return nil
}

func (c *vssClient) getSession(id string) (*vssSession, error) {
	session := vssSession{}
	b, err := c.call(fmt.Sprintf("/api/session/%s", id), "GET")
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(b, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func (c *vssClient) getStatus() (*vssStatus, error) {
	b, err := c.call("/api/status/", "GET")
	if err != nil {
		return nil, err
	}
	status := vssStatus{}
	if err = json.Unmarshal(b, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func newVSSClient(address, key, secret string) *vssClient {
	return &vssClient{
		address:   address,
		apiKey:    key,
		apiSecret: secret,
	}
}
