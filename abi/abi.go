// SPDX-License-Identifier: Apache-2.0

// Package abi — ABI v1 между хостом gate4.ai и коннектором: экспорты модуля,
// функции хоста и их запросы/ответы. Всё передаётся в JSON.
//
// Экспорты WASM-модуля (Go: GOOS=wasip1, -buildmode=c-shared; хост вызывает
// _initialize, затем экспорты; один экземпляр модуля — один вызов):
//
//	gate4ai_alloc(size i32) i32          — буфер в памяти модуля для входных данных
//	gate4ai_manifest() i64               — манифест (JSON)
//	gate4ai_execute(ptr, len i32) i64    — ExecRequest → Response{ExecResult}
//	gate4ai_verify(ptr, len i32) i64     — VerifyRequest → Response{VerifyResult}
//
// Результат i64 — (ptr << 32) | len ответа в памяти модуля.
//
// Импорты модуля (модуль "gate4ai"):
//
//	host_call(fn_ptr, fn_len, req_ptr, req_len i32) i32 — вызов функции хоста fn
//	    с запросом JSON; возвращает длину ответа (Response), ответ ждёт у хоста;
//	host_result(dst i32)                                 — копирует ответ в память модуля.
package abi

import (
	"encoding/json"
	"fmt"
)

// Version — версия ABI.
const Version = 1

// Имена экспортов и импортов.
const (
	ExportAlloc    = "gate4ai_alloc"
	ExportManifest = "gate4ai_manifest"
	ExportExecute  = "gate4ai_execute"
	ExportVerify   = "gate4ai_verify"
	ImportModule   = "gate4ai"
	ImportCall     = "host_call"
	ImportResult   = "host_result"
)

// Функции хоста.
const (
	FnHTTPRequest       = "http_request"
	FnTLSDial           = "tls_dial"
	FnConnRead          = "conn_read"
	FnConnWrite         = "conn_write"
	FnConnClose         = "conn_close"
	FnFSRead            = "fs_read"
	FnFSWrite           = "fs_write"
	FnFSAppend          = "fs_append"
	FnFSList            = "fs_list"
	FnFSStat            = "fs_stat"
	FnKVGet             = "kv_get"
	FnKVSet             = "kv_set"
	FnKVDelete          = "kv_delete"
	FnEvidenceAdd       = "evidence_add"
	FnLog               = "log"
	FnBrowserOpen       = "browser_open"
	FnBrowserObserve    = "browser_observe"
	FnBrowserAct        = "browser_act"
	FnBrowserExtract    = "browser_extract"
	FnBrowserScreenshot = "browser_screenshot_element"
)

// Коды ошибок.
const (
	CodeCapabilityDenied = "capability_denied" // возможность не объявлена в манифесте или сужена политикой
	CodeNotSupported     = "not_supported"     // функция не поддерживается хостом
	CodeBadRequest       = "bad_request"       // неверный запрос
	CodeNotFound         = "not_found"         // файл, соединение, ключ не найдены
	CodeIO               = "io_error"          // ошибка сети или файловой системы
	CodeAuth             = "auth_failed"       // аутентификация хостом не прошла
	CodeLimit            = "limit_exceeded"    // квота, размер, время
	CodeConnector        = "connector_error"   // ошибка самого коннектора
)

// Error — ошибка ABI.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Errorf — ошибка с кодом.
func Errorf(code, f string, a ...any) *Error { return &Error{Code: code, Message: fmt.Sprintf(f, a...)} }

// Response — ответ экспорта модуля и функции хоста.
type Response struct {
	Result json.RawMessage `json:"result,omitempty"`
	Error  *Error          `json:"error,omitempty"`
}

// OK — успешный ответ.
func OK(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return Fail(Errorf(CodeBadRequest, "marshal: %v", err))
	}
	out, _ := json.Marshal(Response{Result: b})
	return out
}

// Fail — ответ с ошибкой.
func Fail(err error) []byte {
	e, ok := err.(*Error)
	if !ok {
		e = &Error{Code: CodeConnector, Message: err.Error()}
	}
	out, _ := json.Marshal(Response{Error: e})
	return out
}

// Decode разбирает ответ в v.
func Decode(resp []byte, v any) error {
	var r Response
	if err := json.Unmarshal(resp, &r); err != nil {
		return Errorf(CodeBadRequest, "bad response: %v", err)
	}
	if r.Error != nil {
		return r.Error
	}
	if v == nil || len(r.Result) == 0 {
		return nil
	}
	return json.Unmarshal(r.Result, v)
}

// ExecRequest — исполнение действия. Settings — настройки экземпляра коннектора
// из конфигурации как есть: секреты в них — только алиасы (@name), значения
// подставляет хост в функциях хоста.
type ExecRequest struct {
	Action   string         `json:"action"`
	Args     map[string]any `json:"args"`
	Settings map[string]any `json:"settings"`
}

// EvidenceItem — доказательство (файл).
type EvidenceItem struct {
	Name string `json:"name"`
	MIME string `json:"mime"`
	Data []byte `json:"data"`
}

// ExecResult — результат исполнения.
type ExecResult struct {
	Result    any            `json:"result"`
	ResultRef string         `json:"result_ref,omitempty"` // идентификатор результата (Message-ID, путь, URL)
	Evidence  []EvidenceItem `json:"evidence,omitempty"`
	Source    string         `json:"source,omitempty"` // источник недоверенного контента: "email:<id>", "web:<url>"
}

// VerifyRequest — проверка результата по независимому каналу.
type VerifyRequest struct {
	Action    string         `json:"action"`
	Args      map[string]any `json:"args"`
	Settings  map[string]any `json:"settings"`
	ResultRef string         `json:"result_ref"`
	Result    any            `json:"result"`
}

// Статусы проверки.
const (
	Verified   = "verified"
	Unverified = "unverified"
	Failed     = "failed"
)

// VerifyResult — итог проверки.
type VerifyResult struct {
	Status   string         `json:"status"`
	Method   string         `json:"method"`
	Detail   string         `json:"detail,omitempty"`
	Evidence []EvidenceItem `json:"evidence,omitempty"`
}

// HTTPRequest — http_request. В заголовках и теле плейсхолдер {{secret:@alias}}
// заменяется хостом значением секрета, только если адрес входит в bind секрета.
// Редиректы хост не выполняет: 3xx возвращается модулю.
type HTTPRequest struct {
	Method    string            `json:"method"`
	URL       string            `json:"url"`
	Headers   map[string]string `json:"headers,omitempty"`
	Body      []byte            `json:"body,omitempty"`
	TimeoutMS int               `json:"timeout_ms,omitempty"`
}

// HTTPResponse — ответ http_request (значения подставленных секретов замаскированы).
type HTTPResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    []byte            `json:"body"`
}

// Режимы TLS для tls_dial.
const (
	TLSDirect   = "tls"      // TLS сразу
	TLSStartTLS = "starttls" // STARTTLS протокола (imap, smtp)
	TLSNone     = "none"     // без TLS — только loopback
)

// Протоколы tls_dial, для которых хост выполняет STARTTLS и аутентификацию.
const (
	ProtoIMAP = "imap"
	ProtoSMTP = "smtp"
)

// Схемы аутентификации хостом.
const (
	AuthIMAPLogin     = "imap-login"      // IMAP LOGIN; модуль получает приветствие PREAUTH
	AuthSMTPAuthPlain = "smtp-auth-plain" // SMTP EHLO + AUTH PLAIN; модуль начинает с MAIL FROM
)

// DialAuth — аутентификация в протоколе, выполняемая хостом.
type DialAuth struct {
	Scheme   string `json:"scheme"`
	Username string `json:"username"`
	Secret   string `json:"secret"` // алиас Vault (@name)
}

// DialRequest — tls_dial. Для Protocol imap хост читает приветствие сервера
// (и выполняет STARTTLS / LOGIN) и отдаёт модулю синтетическое приветствие:
// "* PREAUTH …" после входа или "* OK …" без него. Для smtp хост читает 220,
// выполняет EHLO (STARTTLS, AUTH) — модуль начинает сразу с MAIL FROM.
type DialRequest struct {
	Host     string    `json:"host"`
	Port     int       `json:"port"`
	TLS      string    `json:"tls"`
	Protocol string    `json:"protocol,omitempty"`
	Auth     *DialAuth `json:"auth,omitempty"`
}

// DialResponse — идентификатор соединения.
type DialResponse struct {
	Conn int `json:"conn"`
}

// ConnRead — conn_read: до Max байт, ждать данных не дольше WaitMS (≤ 200).
type ConnRead struct {
	Conn   int `json:"conn"`
	Max    int `json:"max"`
	WaitMS int `json:"wait_ms"`
}

// ConnReadResponse — прочитанные данные; пусто без EOF — данных пока нет.
type ConnReadResponse struct {
	Data []byte `json:"data,omitempty"`
	EOF  bool   `json:"eof,omitempty"`
}

// ConnWrite — conn_write.
type ConnWrite struct {
	Conn int    `json:"conn"`
	Data []byte `json:"data"`
}

// ConnWriteResponse — записано байт.
type ConnWriteResponse struct {
	N int `json:"n"`
}

// ConnClose — conn_close.
type ConnClose struct {
	Conn int `json:"conn"`
}

// FSRequest — fs_read, fs_write, fs_append, fs_list, fs_stat. Путь — абсолютный
// или ~/…; хост раскрывает ~, .. и симлинки и сверяет с capabilities.files.
type FSRequest struct {
	Path string `json:"path"`
	Data []byte `json:"data,omitempty"` // fs_write, fs_append
	Max  int64  `json:"max,omitempty"`  // fs_read: не больше Max байт (по умолчанию 1 МиБ)
}

// FSReadResponse — fs_read.
type FSReadResponse struct {
	Data      []byte `json:"data"`
	Size      int64  `json:"size"`
	Truncated bool   `json:"truncated,omitempty"`
	RealPath  string `json:"real_path"`
}

// FSEntry — элемент каталога.
type FSEntry struct {
	Name string `json:"name"`
	Dir  bool   `json:"dir"`
	Size int64  `json:"size,omitempty"`
}

// FSListResponse — fs_list.
type FSListResponse struct {
	Entries  []FSEntry `json:"entries"`
	RealPath string    `json:"real_path"`
}

// FSStatResponse — fs_stat; Size −1, если файла нет.
type FSStatResponse struct {
	Exists   bool   `json:"exists"`
	Dir      bool   `json:"dir,omitempty"`
	Size     int64  `json:"size"`
	RealPath string `json:"real_path"`
}

// FSWriteResponse — fs_write, fs_append.
type FSWriteResponse struct {
	SizeBefore int64  `json:"size_before"`
	SizeAfter  int64  `json:"size_after"`
	RealPath   string `json:"real_path"`
}

// KVRequest — kv_get, kv_set, kv_delete.
type KVRequest struct {
	Key   string `json:"key"`
	Value []byte `json:"value,omitempty"`
}

// KVResponse — kv_get.
type KVResponse struct {
	Value []byte `json:"value,omitempty"`
	Found bool   `json:"found"`
}

// LogRequest — log (значения секретов хост вырезает).
type LogRequest struct {
	Level string `json:"level"` // debug | info | warn | error
	Msg   string `json:"msg"`
}

// BrowserRequest — browser_open (URL), browser_observe (MaxChars),
// browser_extract (Instruction), browser_screenshot_element (Selector),
// browser_act (Selector + Method — только наблюдённое действие).
type BrowserRequest struct {
	URL         string `json:"url,omitempty"`
	MaxChars    int    `json:"max_chars,omitempty"`
	Instruction string `json:"instruction,omitempty"`
	Selector    string `json:"selector,omitempty"`
	Method      string `json:"method,omitempty"`
}

// BrowserPage — страница: адрес после редиректов, заголовок, текст (observe).
type BrowserPage struct {
	URL       string `json:"url"`
	Title     string `json:"title"`
	Text      string `json:"text,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
}

// BrowserExtractResponse — browser_extract.
type BrowserExtractResponse struct {
	Data any `json:"data"`
}

// BrowserScreenshotResponse — browser_screenshot_element (PNG).
type BrowserScreenshotResponse struct {
	PNG []byte `json:"png"`
}
