package main

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type tr069State uint8

const (
	tr069WaitingForInform tr069State = iota
	tr069WaitingForEmpty
	tr069WaitingForGetParamNamesResponse
	tr069WaitingForGetParamValuesResponse
	tr069Done
)

type tr069Session struct {
	state      tr069State
	paramNames []string
	params     map[string]string
	messageID  int
}

func newTR069Session() *tr069Session {
	return &tr069Session{
		state:  tr069WaitingForInform,
		params: make(map[string]string),
	}
}

func (t *tr069Session) nextID() string {
	t.messageID++
	return fmt.Sprintf("%d", t.messageID)
}

func (t *tr069Session) handleRequest(body string, w http.ResponseWriter) {
	switch t.state {
	case tr069WaitingForInform:
		t.handleInform(body, w)
	case tr069WaitingForEmpty:
		t.handleEmpty(body, w)
	case tr069WaitingForGetParamNamesResponse:
		t.handleGetParameterNamesResponse(body, w)
	case tr069WaitingForGetParamValuesResponse:
		t.handleGetParameterValuesResponse(body, w)
	case tr069Done:
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (t *tr069Session) handleInform(body string, w http.ResponseWriter) {
	log.Printf("TR-069: received Inform")
	t.state = tr069WaitingForEmpty
	writeSOAPResponse(w, t.nextID(), informResponseBody)
}

func (t *tr069Session) handleEmpty(body string, w http.ResponseWriter) {
	log.Printf("TR-069: received empty POST, sending GetParameterNames")
	t.state = tr069WaitingForGetParamNamesResponse
	id := t.nextID()
	gpn := fmt.Sprintf(getParameterNamesBody, "InternetGatewayDevice.", "false")
	writeSOAPResponse(w, id, gpn)
}

func (t *tr069Session) handleGetParameterNamesResponse(body string, w http.ResponseWriter) {
	names := parseParameterNames(body)
	log.Printf("TR-069: received %d parameter names", len(names))
	t.paramNames = names

	for _, name := range names {
		log.Printf("TR-069 param: %s", name)
	}

	if len(names) == 0 {
		log.Printf("TR-069: no parameters found, ending session")
		t.state = tr069Done
		w.Header().Set("Content-Length", "0")
		w.WriteHeader(http.StatusNoContent)
		return
	}

	t.state = tr069WaitingForGetParamValuesResponse
	id := t.nextID()
	gpv := buildGetParameterValues(names)
	writeSOAPResponse(w, id, gpv)
}

func (t *tr069Session) handleGetParameterValuesResponse(body string, w http.ResponseWriter) {
	values := parseParameterValues(body)
	log.Printf("TR-069: received %d parameter values", len(values))
	for name, value := range values {
		t.params[name] = value
	}

	t.state = tr069Done
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusNoContent)
}

func writeSOAPResponse(w http.ResponseWriter, id string, body string) {
	envelope := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:SOAP-ENC="http://schemas.xmlsoap.org/soap/encoding/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
<SOAP-ENV:Header>
<cwmp:ID SOAP-ENV:mustUnderstand="1">%s</cwmp:ID>
</SOAP-ENV:Header>
<SOAP-ENV:Body>
%s
</SOAP-ENV:Body>
</SOAP-ENV:Envelope>`, id, body)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(envelope))
}

const informResponseBody = `<cwmp:InformResponse>
<MaxEnvelopes>1</MaxEnvelopes>
</cwmp:InformResponse>`

const getParameterNamesBody = `<cwmp:GetParameterNames>
<ParameterPath>%s</ParameterPath>
<NextLevel>%s</NextLevel>
</cwmp:GetParameterNames>`

func buildGetParameterValues(names []string) string {
	var items strings.Builder
	for _, name := range names {
		items.WriteString(fmt.Sprintf("<string>%s</string>\n", xmlEscape(name)))
	}
	return fmt.Sprintf(`<cwmp:GetParameterValues>
<ParameterNames SOAP-ENC:arrayType="xsd:string[%d]">
%s</ParameterNames>
</cwmp:GetParameterValues>`, len(names), items.String())
}

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

type soapEnvelope struct {
	Body soapBody `xml:"Body"`
}

type soapBody struct {
	Inner []byte `xml:",innerxml"`
}

type getParameterNamesResponse struct {
	ParameterList parameterInfoList `xml:"ParameterList"`
}

type parameterInfoList struct {
	Items []parameterInfoStruct `xml:"ParameterInfoStruct"`
}

type parameterInfoStruct struct {
	Name     string `xml:"Name"`
	Writable string `xml:"Writable"`
}

type getParameterValuesResponse struct {
	ParameterList parameterValueList `xml:"ParameterList"`
}

type parameterValueList struct {
	Items []parameterValueStruct `xml:"ParameterValueStruct"`
}

type parameterValueStruct struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

func parseParameterNames(body string) []string {
	var env soapEnvelope
	if err := xml.Unmarshal([]byte(body), &env); err != nil {
		log.Printf("TR-069: failed to parse SOAP envelope: %v", err)
		return nil
	}

	var resp getParameterNamesResponse
	if err := xml.Unmarshal(env.Body.Inner, &resp); err != nil {
		log.Printf("TR-069: failed to parse GetParameterNamesResponse: %v", err)
		return nil
	}

	var names []string
	for _, item := range resp.ParameterList.Items {
		name := strings.TrimSpace(item.Name)
		if name != "" && !strings.HasSuffix(name, ".") {
			names = append(names, name)
		}
	}
	return names
}

func parseParameterValues(body string) map[string]string {
	var env soapEnvelope
	if err := xml.Unmarshal([]byte(body), &env); err != nil {
		log.Printf("TR-069: failed to parse SOAP envelope: %v", err)
		return nil
	}

	var resp getParameterValuesResponse
	if err := xml.Unmarshal(env.Body.Inner, &resp); err != nil {
		log.Printf("TR-069: failed to parse GetParameterValuesResponse: %v", err)
		return nil
	}

	values := make(map[string]string)
	for _, item := range resp.ParameterList.Items {
		name := strings.TrimSpace(item.Name)
		if name != "" {
			values[name] = item.Value
		}
	}
	return values
}
