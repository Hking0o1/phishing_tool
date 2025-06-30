# Phishing Tool

A basic phishing site detection tool which uses three different services in parallel.

---

## Features

- **Multi-Service Detection:**  
  Simultaneously checks URLs against three different phishing detection services for higher accuracy and reliability.

- **Real-Time Analysis:**  
  Processes user-supplied URLs instantly and returns consolidated results from all services.

- **User-Friendly Interface:**  
  Clean HTML/JavaScript interface for quick and easy URL testing.

- **Extensible:**  
  Easily add or swap detection services as needed.

---

## Usage

### 1. Clone the Repository

```bash
git clone https://github.com/Hking0o1/phishing_tool.git
cd phishing_tool
```

### 2. Open the Tool

Open `index.html` in your web browser.

### 3. Enter a URL

- Type or paste the URL you want to check for phishing.
- Click **Check** or the relevant button.

### 4. View Results

- The tool will query all three detection services in parallel.
- Results will be displayed, indicating whether the URL is safe, suspicious, or flagged as phishing by each service.

---

## Dependencies

- No server-side requirements—runs entirely in the browser.
- Requires an internet connection to reach the phishing detection services' APIs.

---

## Configuration

- API keys or endpoints for the detection services may need to be set in the JavaScript files.
- See comments in `script.js` for details on configuring or adding services.

---

## Contributions

Contributions and suggestions are welcome!  
Open an issue or submit a pull request.

---
