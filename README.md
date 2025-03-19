AI-Powered Phishing Email Detector
AI-Powered Phishing Email Detector is a Python desktop application that scans your Gmail inbox and uses OpenAI’s API to analyze emails for potential phishing attempts. The application features a user-friendly profile management system—allowing you to create, edit, or delete profiles (up to 5)—and displays email details and AI analysis in a clean, modern Tkinter-based GUI.

Features
IMAP Email Connectivity: Connects to your Gmail account using IMAP with app passwords.
Phishing Analysis: Uses OpenAI’s GPT model to assess emails for phishing risks.
Profile Management: Create, edit, and delete up to 5 profiles with real-time updates in the GUI.
Dynamic Interface: Easily change profiles without restarting the application.
Multi-threaded Email Processing: Efficiently retrieves and processes emails using threads and concurrent futures.
Important Security Note
Gmail Security Requirements:
Your normal Gmail password will not work with this application.
To use Gmail, you must enable Two-Factor Authentication (2FA).
Generate an App Password from your Google Account settings and use that in the application.
Required Libraries
This application requires the following Python libraries:

Standard Libraries:

imaplib, email, smtplib, time, json, os, re, webbrowser, threading, queue, concurrent.futures, datetime, keyring
Third-Party Libraries:

Tkinter (usually included with Python)
OpenAI – For connecting to the OpenAI API
html2text – For converting HTML email content to plain text
tkinterweb (optional) – For in-app full HTML rendering
Pillow (PIL) – For generating profile icons in the GUI
Installation
Clone the Repository:

bash
Copy
git clone https://github.com/yourusername/ai-phishing-email-detector.git
cd ai-phishing-email-detector
Set Up a Virtual Environment (Optional but Recommended):

bash
Copy
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
Install the Required Libraries:

bash
Copy
pip install openai html2text keyring Pillow tkinterweb
Note: Tkinter is typically included with Python. If not, please refer to your operating system’s instructions to install it.

Usage
Gmail Configuration:

Enable IMAP in your Gmail account.
Enable 2FA: Your normal Gmail password will not work. Enable Two-Factor Authentication.
Generate an App Password from your Google Account settings and use it in the application.
Run the Application:

bash
Copy
python your_script_name.py
Select a Profile:

At startup, a profile selection screen will appear.
Choose an existing profile or click Manage Profiles to create, edit, or delete profiles.
Changes are reflected in real time.
Email Analysis:

After selecting a profile, the main window opens.
The application connects to Gmail using your profile’s credentials and scans your inbox.
Emails are displayed along with an AI-generated analysis indicating the phishing risk.
You can change profiles anytime by clicking the Change Profile button.
Code Overview
ProfileManager Class:
Manages profile creation, editing, deletion, and selection using a straightforward GUI. All changes update immediately.

PhishingDetector Class:
Connects to Gmail via IMAP, retrieves emails, and uses OpenAI’s API to analyze them. The class also manages the main interface for displaying email details and analysis and allows for dynamic profile switching.

Real-Time Updates:
Any modifications to profiles (create, edit, or delete) are reflected instantly in the GUI without needing to restart the application.
