# CodeNova Task 2 — Phishing Awareness Analyzer (Website)

A browser-based URL phishing-awareness analyzer built with HTML, CSS and JavaScript.

## Run
Open `index.html` in a browser, or use VS Code Live Server.

## Test
Requires Node.js. Run `npm test` in the project folder.

## URL heuristics
- Non-HTTPS scheme: +10
- IP-based host: +25
- Embedded user information: +25
- Possible lookalike brand domain: +25
- Four or more hostname labels: +10 (not applied to IP addresses)

Risk bands: Low 0–29, Medium 30–59, High 60–100.

## Privacy and safety
The analyzer parses URL text locally in the browser. It does not open submitted URLs, perform DNS/HTTP requests, or send the input to a server. Do not enter private credentials. Findings are heuristic signals, not proof of phishing; false positives and false negatives are possible.

## Current scope
This version implements URL analysis. Email body/header analysis is the next planned feature.
