# refxss

`refxss` is a fast, lightweight reflected-XSS parameter discovery tool inspired by **kxss**, written in Go.

It helps bug bounty hunters and security researchers quickly identify reflected parameters and unfiltered special characters that may lead to XSS.

---

## ✨ Features

- Reflected parameter detection (kxss-style)
- Special character filtering (`' " < > ( ) { }` etc.)
- Groups all vulnerable parameters per URL
- Handles escaped URLs (`\? \= \&`)
- Works with encoded / decoded reflections
- Concurrent and fast
- Custom headers support
- Clean, readable output

---

## 🔧 Installation

```bash
go install github.com/suchinsuthar/refxss@latest
```

## Usage
```
echo "https://target.com/path?query=parame&another=param2" | refxss
```

### Any question
[Email](mailto:suchinsuthar@gmail.com?subject=github%3Arefxss)
