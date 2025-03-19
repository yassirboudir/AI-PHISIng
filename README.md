# AI-Powered Phishing Email Detector

**AI-Powered Phishing Email Detector** is a Python desktop application that scans your Gmail inbox and uses OpenAI’s API to analyze emails for potential phishing attempts. The application features a user-friendly profile management system—allowing you to create, edit, or delete profiles (up to 5)—and displays email details and AI analysis in a clean, modern Tkinter-based GUI.

---

## Features

- **IMAP Email Connectivity:** Connect to your Gmail account using IMAP with app passwords.
- **Phishing Analysis:** Uses OpenAI’s GPT model to assess emails for phishing risks.
- **Profile Management:** Create, edit, and delete up to 5 profiles with real-time updates in the GUI.
- **Dynamic Interface:** Easily change profiles without restarting the application.
- **Multi-threaded Email Processing:** Efficiently retrieves and processes emails using threads and concurrent futures.

---

## Important Security Note

- **Gmail Security Requirements:**
  - Your normal Gmail password **will not work** with this application.
  - You must **enable Two-Factor Authentication (2FA)** for Gmail.
  - Generate an **App Password** from your Google Account settings to use with this application.

---

## Required Libraries

This application requires the following Python libraries:

### Standard Libraries

- `imaplib`, `email`, `smtplib`, `time`, `json`, `os`, `re`, `webbrowser`, `threading`, `queue`, `concurrent.futures`, `datetime`, `keyring`

### Third-Party Libraries

- [**Tkinter**](https://docs.python.org/3/library/tkinter.html) *(usually included with Python)*
- [**OpenAI**](https://pypi.org/project/openai/) – Connect to the OpenAI API
- [**html2text**](https://pypi.org/project/html2text/) – Convert HTML email content to plain text
- [**tkinterweb**](https://pypi.org/project/tkinterweb/) *(optional)* – In-app full HTML rendering
- [**Pillow (PIL)**](https://pypi.org/project/Pillow/) – Generate profile icons in the GUI

---

## Installation

### 1\. Clone the Repository

```bash
git clone https://github.com/yourusername/ai-phishing-email-detector.git
cd ai-phishing-email-detector
```

### 2\. Set Up a Virtual Environment *(Optional but Recommended)*

```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

### 3\. Install Required Libraries

```bash
pip install openai html2text keyring Pillow tkinterweb
```

> **Note:** Tkinter is typically included with Python. If not, refer to your OS documentation for installation.

---

## Usage

### 1\. Gmail Configuration

- Enable **IMAP** in your Gmail account.
- Enable **Two-Factor Authentication (2FA)**. *(Your normal password won't work.)*
- Generate an **App Password** from your Google Account settings and use it in the application.

### 2\. Run the Application

```bash
python your_script_name.py
```

### 3\. Select a Profile

- At startup, select an existing profile or click **Manage Profiles** to create, edit, or delete profiles.
- Changes update in real-time.

### 4\. Email Analysis

- After selecting a profile, the application connects to Gmail, scans emails, and provides AI-generated phishing risk analysis.
- Change profiles at any time using the **Change Profile** button.

---

## Code Overview

### `ProfileManager` Class
- Handles creation, editing, deletion, and selection of profiles with real-time GUI updates.

### `PhishingDetector` Class
- Connects to Gmail via IMAP, retrieves emails, analyzes content with OpenAI’s API, and manages the primary GUI interface.

### Real-Time Updates
- Profile changes reflect instantly in the GUI, no restart required.
