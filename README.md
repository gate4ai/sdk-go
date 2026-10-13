# gate4ai sdk-go

SDK коннекторов [gate4.ai](https://github.com/gate4ai/gate4ai) на Go. Это контракт между хостом и коннектором: манифест, ABI v1 и функции хоста.

| Пакет | Что это |
|---|---|
| `manifest` | манифест: действия, аргументы, класс эффекта, проверка результата, `runtime`, `capabilities`, `limits`; шаблоны `${setting:…}` |
| `abi` | ABI v1: экспорты модуля, функции хоста, их запросы и ответы; `abi.Host` — типизированные функции хоста для кода коннектора |
| `connector` | PDK: `connector.Register` и экспорты WASM-модуля (`GOOS=wasip1`) |
| `capability` | проверка вызовов по возможностям манифеста (`capability_denied`) |
| `hostfuncs` | реализация функций хоста поверх служб хоста; та же, что в хосте gate4.ai |
| `netauth` | TLS, STARTTLS и аутентификация хостом в IMAP/SMTP — коннектор не видит пароль |
| `hosttest` | хост в том же процессе для нативных тестов коннектора |
| `domain` | сопоставление адресов с шаблонами доменов |

## Принципы

- Коннектор пользуется только функциями хоста: сети, файлов, процессов и переменных окружения у WASM-модуля нет.
- Всё, что не объявлено в `capabilities` манифеста, недоступно: функция хоста вернёт `capability_denied`. Политика пользователя может возможности только сузить.
- Коннектор не видит секреты: в настройках — только алиасы (`@mail.work`), значения подставляет хост (`{{secret:@alias}}` в `http_request`, аутентификация в `tls_dial`) и только для адресов из `bind`.

## Коннектор за пять минут

```go
package main

import (
	"context"
	_ "embed"

	"github.com/gate4ai/sdk-go/abi"
	"github.com/gate4ai/sdk-go/connector"
)

//go:embed manifest.yaml
var manifestYAML []byte

type Hello struct{}

func (Hello) Execute(ctx context.Context, h *abi.Host, r abi.ExecRequest) (abi.ExecResult, error) {
	resp, err := h.HTTP(abi.HTTPRequest{URL: "https://api.example.com/hello",
		Headers: map[string]string{"Authorization": "Bearer {{secret:@example}}"}})
	if err != nil {
		return abi.ExecResult{}, err
	}
	return abi.ExecResult{Result: string(resp.Body)}, nil
}

func (Hello) Verify(context.Context, *abi.Host, abi.VerifyRequest) (abi.VerifyResult, error) {
	return abi.VerifyResult{Status: abi.Unverified, Method: "none"}, nil
}

func init() { connector.Register(manifestYAML, Hello{}) }
func main() {}
```

```yaml
connector: hello
version: 1.0.0
runtime: wasm
capabilities:
  network: [ { host: api.example.com, scheme: https } ]
  secrets: [ { alias: "@example", bind: [api.example.com] } ]
actions:
  - { name: say, class: read }
```

```sh
GOOS=wasip1 GOARCH=wasm go build -buildmode=c-shared -o connector.wasm .
```

Тесты — нативно, на `hosttest` (те же проверки возможностей, что в хосте). Примеры — коннекторы `gate4ai-mail`, `gate4ai-files`, `gate4ai-browser`.

## ABI v1

Описание экспортов и импортов — в документации пакета [`abi`](abi/abi.go). Один экземпляр модуля обслуживает один вызов; лимиты памяти и времени — `limits` манифеста.

## Лицензия

[Apache-2.0](LICENSE). Коннекторы на этом SDK могут иметь любую совместимую лицензию; официальные коннекторы gate4.ai — AGPL-3.0 с исключением для хоста.
