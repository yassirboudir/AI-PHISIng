import imaplib
import email
import email.header
import smtplib
import time
import json
import os
import re
import webbrowser
import threading
from queue import Queue
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from openai import OpenAI
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import keyring
from datetime import datetime

# For HTML conversion (fallback)
import html2text
from email.utils import parseaddr  # For extracting display name and email address

# Attempt to import tkinterweb for in-app full HTML rendering
try:
    from tkinterweb import HtmlFrame
    HAVE_TKINTERWEB = True
except ImportError:
    HAVE_TKINTERWEB = False

# For creating round images
try:
    from PIL import Image, ImageDraw, ImageTk
    HAVE_PIL = True
except ImportError:
    HAVE_PIL = False

##############################
# Profile Manager Definition #
##############################
class ProfileManager:
    """
    Shows a Netflix-style 'Please Select Your Profile or create a new one' profile selection screen.
    Each profile is displayed as a circular colored icon with the profile name underneath.
    You can also click 'Manage Profiles' to create/edit/delete them in a classic list view.
    """
    def __init__(self, master):
        self.master = master
        self.master.title("Select Profile")
        self.master.geometry("600x400")
        self.profiles_file = "profiles.json"
        self.profiles = self.load_profiles()
        self.selected_profile = None
        
        # In-memory color palette for up to 5 profiles
        self.colors = ["#E50914", "#F5C518", "#0092FF", "#777777", "#00BB00"]
        
        self.create_widgets()
    
    def load_profiles(self):
        if os.path.exists(self.profiles_file):
            try:
                with open(self.profiles_file, "r") as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading profiles: {e}")
                return []
        return []
    
    def save_profiles(self):
        with open(self.profiles_file, "w") as f:
            json.dump(self.profiles, f, indent=4)
    
    def create_widgets(self):
        """Draw the Netflix‐style UI (title, circular icons, and Manage Profiles button)."""
        # Netflix-like dark background
        self.master.configure(bg="#141414")
        
        # Title
        title_label = tk.Label(
            self.master,
            text="Please Select Your Profile or create a new one",
            fg="white",
            bg="#141414",
            font=("Arial", 20, "bold")
        )
        title_label.pack(pady=20)
        
        # Frame to hold the profile icons
        self.profiles_frame = tk.Frame(self.master, bg="#141414")
        self.profiles_frame.pack()
        
        # Create a circular button for each profile
        for i, profile in enumerate(self.profiles):
            color = self.colors[i % len(self.colors)]
            
            # Create a circular image
            circle_img = self.create_circle_image(100, color)
            
            # Profile icon button
            btn = tk.Button(
                self.profiles_frame,
                image=circle_img,
                bd=0,
                highlightthickness=0,
                bg="#141414",
                activebackground="#141414",
                command=lambda idx=i: self.select_profile_idx(idx)
            )
            # Keep a reference to avoid garbage collection
            btn.image = circle_img
            btn.grid(row=0, column=i, padx=15)
            
            # Name label under the circle
            name = profile.get("profile_name", "Unknown")
            name_label = tk.Label(
                self.profiles_frame,
                text=name,
                fg="white",
                bg="#141414",
                font=("Arial", 12)
            )
            name_label.grid(row=1, column=i, pady=5)
        
        # Manage Profiles button
        manage_btn = tk.Button(
            self.master,
            text="Manage Profiles",
            font=("Arial", 10),
            fg="white",
            bg="#333333",
            activebackground="#333333",
            command=self.manage_profiles
        )
        manage_btn.pack(pady=10)
    
    def create_circle_image(self, diameter, color):
        """
        Creates a circular image in memory using PIL. 
        If Pillow is not installed, returns a blank image.
        """
        if not HAVE_PIL:
            # Fallback: Return a tiny 1x1 image if PIL is missing
            return tk.PhotoImage(width=1, height=1)
        
        img = Image.new("RGBA", (diameter, diameter), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        draw.ellipse((0, 0, diameter, diameter), fill=color)
        return ImageTk.PhotoImage(img)
    
    def select_profile_idx(self, idx):
        """User clicked on a profile icon."""
        if idx < 0 or idx >= len(self.profiles):
            return
        self.selected_profile = self.profiles[idx]
        self.master.destroy()
    
    def manage_profiles(self):
        """
        Opens a simple list-based manager to create/edit/delete profiles.
        """
        mgr = tk.Toplevel(self.master)
        mgr.title("Manage Profiles")
        mgr.geometry("400x300")
        
        frame = ttk.Frame(mgr)
        frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.profile_listbox = tk.Listbox(frame)
        self.profile_listbox.pack(fill=tk.BOTH, expand=True)
        
        self.refresh_profile_list()
        
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=5)
        
        ttk.Button(btn_frame, text="Create", command=self.create_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Edit", command=self.edit_profile).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Delete", command=self.delete_profile).pack(side=tk.LEFT, padx=5)
        
        close_btn = ttk.Button(frame, text="Close", command=mgr.destroy)
        close_btn.pack(pady=5)
    
    def refresh_profile_list(self):
        """Refresh the listbox in the Manage Profiles Toplevel."""
        if not hasattr(self, 'profile_listbox'):
            return
        self.profile_listbox.delete(0, tk.END)
        for profile in self.profiles:
            name = profile.get("profile_name", "Unknown Profile")
            self.profile_listbox.insert(tk.END, name)
    
    def refresh_netflix_view(self):
        """
        Refresh the Netflix‐style UI in real time. 
        Reload profiles, destroy all widgets, then re-create them.
        """
        self.profiles = self.load_profiles()  # re-load from file
        for widget in self.master.winfo_children():
            widget.destroy()
        self.create_widgets()
    
    def create_profile(self):
        if len(self.profiles) >= 5:
            messagebox.showerror("Error", "Maximum of 5 profiles allowed.")
            return
        profile = self.profile_dialog()
        if profile:
            self.profiles.append(profile)
            self.save_profiles()
            self.refresh_profile_list()
            self.refresh_netflix_view()  # <-- update Netflix UI in real time
    
    def edit_profile(self):
        if not hasattr(self, 'profile_listbox'):
            return
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Select a profile to edit.")
            return
        index = selection[0]
        current = self.profiles[index]
        updated = self.profile_dialog(current)
        if updated:
            self.profiles[index] = updated
            self.save_profiles()
            self.refresh_profile_list()
            self.refresh_netflix_view()  # <-- update Netflix UI in real time
    
    def delete_profile(self):
        if not hasattr(self, 'profile_listbox'):
            return
        selection = self.profile_listbox.curselection()
        if not selection:
            messagebox.showerror("Error", "Select a profile to delete.")
            return
        index = selection[0]
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this profile?")
        if confirm:
            del self.profiles[index]
            self.save_profiles()
            self.refresh_profile_list()
            self.refresh_netflix_view()  # <-- update Netflix UI in real time
    
    def profile_dialog(self, profile=None):
        dialog = tk.Toplevel(self.master)
        dialog.title("Profile Details")
        dialog.grab_set()
        
        fields = {
            "profile_name": "Profile Name",
            "email": "Email Address",
            "password": "Password",
            "openai_api_key": "OpenAI API Key"
        }
        entries = {}
        
        for i, (key, label_text) in enumerate(fields.items()):
            ttk.Label(dialog, text=label_text + ":").grid(row=i, column=0, padx=5, pady=5, sticky="w")
            entry = ttk.Entry(dialog, width=30, show="*" if key in ["password", "openai_api_key"] else None)
            entry.grid(row=i, column=1, padx=5, pady=5)
            if profile and key in profile:
                entry.insert(0, profile[key])
            entries[key] = entry
        
        def on_submit():
            result = {}
            for key, entry in entries.items():
                value = entry.get().strip()
                if not value:
                    messagebox.showerror("Error", f"{fields[key]} cannot be empty.")
                    return
                result[key] = value
            dialog.result = result
            dialog.destroy()
        
        submit_btn = ttk.Button(dialog, text="Save", command=on_submit)
        submit_btn.grid(row=len(fields), column=0, columnspan=2, pady=10)
        
        dialog.wait_window()
        return getattr(dialog, "result", None)

#########################################
# PhishingDetector Application          #
#########################################
class PhishingDetector:
    def __init__(self, profile, root):
        self.profile = profile
        self.email_account = profile["email"]
        self.email_password = profile["password"]
        self.openai_api_key = profile["openai_api_key"]
        # Preselected IMAP server and port
        self.imap_server = "imap.gmail.com"
        self.imap_port = 993
        
        self.root = root  # Use the existing root instance
        self.root.title("AI-Powered Phishing Email Detector")
        self.root.geometry("1200x700")
        self.root.resizable(True, True)
        
        self.imap_connection = None
        self.openai_client = None
        self.emails = []
        self.polling_thread = None
        self.is_polling = False
        
        # For batch processing and threading
        self.processing_queue = Queue()
        self.email_cache = {}  # Cache analyzed emails
        self.executor = ThreadPoolExecutor(max_workers=3)
        
        # Track offset for loading older emails (now scanning 25 emails at a time)
        self.email_offset = 0
        self.force_newest = True
        
        self.setup_ui()
        self.connect_to_email()
    
    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TFrame", background="#f0f0f0")
        style.configure("TLabel", background="#f0f0f0", font=("Arial", 10))
        style.configure("TButton", font=("Arial", 10, "bold"))
        style.configure("Treeview.Heading", font=("Arial", 10, "bold"))
        style.configure("Treeview", font=("Arial", 10))
        
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Top frame: Display active profile and new "Change Profile" + "Disconnect" buttons
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(
            top_frame, 
            text=f"Profile: {self.profile['profile_name']}", 
            font=("Arial", 12, "bold")
        ).pack(side=tk.LEFT)
        
        # 1) Add the "Change Profile" button
        self.change_profile_button = ttk.Button(top_frame, text="Change Profile", command=self.change_profile)
        self.change_profile_button.pack(side=tk.RIGHT, padx=5)
        
        # Disconnect button
        self.disconnect_button = ttk.Button(top_frame, text="Disconnect", command=self.disconnect)
        self.disconnect_button.pack(side=tk.RIGHT, padx=5)
        
        # Left column: Email Inbox
        left_column = ttk.Frame(main_frame)
        left_column.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Right column: Email Details and AI Analysis
        right_column = ttk.Frame(main_frame)
        right_column.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        right_column.rowconfigure(0, weight=2)
        right_column.rowconfigure(1, weight=1)
        right_column.columnconfigure(0, weight=1)
        
        # --- Email Inbox Section ---
        list_frame = ttk.LabelFrame(left_column, text="Email Inbox")
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.email_tree = ttk.Treeview(list_frame, columns=("sender", "subject", "date", "status"), show="headings")
        self.email_tree.heading("sender", text="Sender")
        self.email_tree.heading("subject", text="Subject")
        self.email_tree.heading("date", text="Date")
        self.email_tree.heading("status", text="Status")
        
        self.email_tree.column("sender", width=150)
        self.email_tree.column("subject", width=300)
        self.email_tree.column("date", width=120)
        self.email_tree.column("status", width=80)
        
        self.email_tree.pack(fill=tk.BOTH, expand=True)
        self.email_tree.bind("<<TreeviewSelect>>", self.show_email_details)
        
        scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.email_tree.yview)
        self.email_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.load_older_button = ttk.Button(list_frame, text="← Older", command=self.load_older_emails)
        self.load_older_button.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.load_newest_button = ttk.Button(list_frame, text="→ Newest", command=self.load_newest_emails)
        self.load_newest_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # --- Email Details Section ---
        details_frame = ttk.LabelFrame(right_column, text="Email Details")
        details_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        if HAVE_TKINTERWEB:
            self.email_details = HtmlFrame(details_frame, horizontal_scrollbar="auto")
            self.email_details.pack(fill="both", expand=True)
        else:
            self.email_details = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD)
            self.email_details.configure(font=("Arial", 10))
            self.email_details.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            self.view_html_button = ttk.Button(details_frame, text="View Original HTML", command=self.view_html)
            self.view_html_button.pack(side=tk.BOTTOM, pady=5)
        
        # --- AI Analysis Section ---
        analysis_frame = ttk.LabelFrame(right_column, text="AI Analysis")
        analysis_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=10)
        
        self.analysis_text = scrolledtext.ScrolledText(analysis_frame, wrap=tk.WORD, height=8)
        self.analysis_text.configure(font=("Arial", 10))
        self.analysis_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # --- Status Bar ---
        status_frame = ttk.Frame(self.root)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Not connected")
        status_bar = ttk.Label(status_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.progress_var = tk.StringVar()
        self.progress_var.set("")
        self.progress_label = ttk.Label(status_frame, textvariable=self.progress_var, width=20)
        self.progress_label.pack(side=tk.RIGHT, padx=5)
        
        self.root.after(100, self.process_queue)
    
    def connect_to_email(self):
        try:
            self.openai_client = OpenAI(api_key=self.openai_api_key)
            self.imap_connection = imaplib.IMAP4_SSL(self.imap_server, self.imap_port)
            self.imap_connection.login(self.email_account, self.email_password)
            self.status_var.set(f"Connected to {self.email_account}")
            self.disconnect_button.config(text="Disconnect", command=self.disconnect)
            
            self.is_polling = True
            self.polling_thread = threading.Thread(target=self.poll_emails, daemon=True)
            self.polling_thread.start()
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {str(e)}")
            self.status_var.set("Connection failed")
    
    def disconnect(self):
        if self.imap_connection:
            self.is_polling = False
            threading.Thread(target=self._disconnect_thread, daemon=True).start()
            self.status_var.set("Disconnecting...")
    
    def _disconnect_thread(self):
        try:
            self.imap_connection.logout()
        except:
            pass
        self.imap_connection = None
        self.root.after(0, lambda: self.status_var.set("Disconnected"))
        self.root.after(0, lambda: self.disconnect_button.config(text="Connect", command=self.connect_to_email))
        self.root.after(0, lambda: self.email_tree.delete(*self.email_tree.get_children()))
    
    def poll_emails(self):
        while self.is_polling:
            try:
                if self.force_newest:
                    self.email_offset = 0
                    self.load_email_chunk(0)
                current_time = datetime.now().strftime('%H:%M:%S')
                self.root.after(0, lambda t=current_time: self.status_var.set(
                    f"Connected to {self.email_account} - Last checked: {t}"
                ))
            except Exception as e:
                self.root.after(0, lambda e=e: self.status_var.set(f"Error: {str(e)}"))
            time.sleep(60)
    
    def load_email_chunk(self, offset=0):
        threading.Thread(target=self._fetch_emails_thread, args=(offset,), daemon=True).start()
    
    def _fetch_emails_thread(self, offset):
        if not self.imap_connection:
            return
        try:
            self.imap_connection.select('INBOX')
            status, email_ids = self.imap_connection.search(None, 'ALL')
            if status != 'OK':
                return
            email_id_list = email_ids[0].split()
            total_emails = len(email_id_list)
            
            if offset >= total_emails:
                self.root.after(0, lambda: messagebox.showinfo("Info", "No more older emails."))
                return
            
            # Scan 25 emails at a time
            start_index = max(0, total_emails - offset - 25)
            end_index = total_emails - offset
            chunk = email_id_list[start_index:end_index]
            
            self.root.after(0, lambda: self.email_tree.delete(*self.email_tree.get_children()))
            
            emails_to_process = []
            for email_id in chunk:
                email_id_str = email_id.decode('utf-8')
                if email_id_str in self.email_cache:
                    continue
                emails_to_process.append(email_id)
            
            total_to_process = len(emails_to_process)
            self.root.after(0, lambda t=total_to_process: self.progress_var.set(f"Loading {t} emails..."))
            
            BATCH_SIZE = 3
            processed_count = 0
            for i in range(0, len(emails_to_process), BATCH_SIZE):
                batch = emails_to_process[i:i+BATCH_SIZE]
                for email_id in batch:
                    fetch_status, email_data = self.imap_connection.fetch(email_id, '(RFC822)')
                    if fetch_status != 'OK':
                        continue
                    raw_email = email_data[0][1]
                    email_message = email.message_from_bytes(raw_email)
                    self.processing_queue.put((email_id, email_message))
                    self.email_cache[email_id.decode('utf-8')] = "processing"
                processed_count += len(batch)
                self.root.after(0, lambda p=processed_count, t=total_to_process: 
                                self.progress_var.set(f"Fetched {p}/{t} emails"))
            
            self.root.after(0, lambda: self.insert_processed_emails(chunk))
            self.root.after(1000, lambda: self.progress_var.set("Processing emails..."))
        except Exception as e:
            print(f"Error in _fetch_emails_thread: {e}")
    
    def insert_processed_emails(self, chunk):
        chunk_ids = [cid.decode('utf-8') for cid in chunk]
        for em in reversed(self.emails):
            if em['id'] in chunk_ids:
                status_icon = "✓" if em['analysis']['is_safe'] else "✗"
                self.email_tree.insert("", 0, values=(
                    em['sender'], em['subject'], em['date'], status_icon, em['id']
                ))
    
    def load_older_emails(self):
        self.force_newest = False
        self.email_offset += 25
        self.load_email_chunk(self.email_offset)
    
    def load_newest_emails(self):
        self.force_newest = True
        self.email_offset = 0
        self.load_email_chunk(0)
    
    def process_queue(self):
        try:
            queue_size = self.processing_queue.qsize()
            process_count = min(3, queue_size)
            if process_count > 0:
                self.progress_var.set(f"Analyzing {queue_size} emails...")
                for _ in range(process_count):
                    if not self.processing_queue.empty():
                        email_id, email_message = self.processing_queue.get_nowait()
                        self.executor.submit(self.process_email, email_id, email_message)
            else:
                if self.progress_var.get().startswith("Analyzing") or self.progress_var.get().startswith("Processing"):
                    self.progress_var.set("")
        except Exception as e:
            print(f"Error in queue processing: {e}")
        self.root.after(100, self.process_queue)
    
    def process_email(self, email_id, email_message):
        try:
            subject, encoding = email.header.decode_header(email_message['Subject'])[0]
            if isinstance(subject, bytes):
                subject = subject.decode(encoding or 'utf-8', errors='replace')
            
            from_header, encoding = email.header.decode_header(email_message['From'])[0]
            if isinstance(from_header, bytes):
                from_header = from_header.decode(encoding or 'utf-8', errors='replace')
            
            date_str = email_message['Date']
            body = ""
            html_content = ""
            
            if email_message.is_multipart():
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get("Content-Disposition"))
                    if "attachment" not in content_disposition:
                        try:
                            payload = part.get_payload(decode=True)
                            if payload is None:
                                continue
                            charset = part.get_content_charset() or 'utf-8'
                            if content_type == "text/plain":
                                body = payload.decode(charset, errors='replace')
                            elif content_type == "text/html":
                                html_content = payload.decode(charset, errors='replace')
                        except Exception as e:
                            print(f"Error decoding part: {e}")
                            continue
            else:
                try:
                    payload = email_message.get_payload(decode=True)
                    if payload:
                        charset = email_message.get_content_charset() or 'utf-8'
                        if email_message.get_content_type() == "text/html":
                            html_content = payload.decode(charset, errors='replace')
                        else:
                            body = payload.decode(charset, errors='replace')
                except Exception as e:
                    print(f"Error decoding email: {e}")
            
            if not body and html_content:
                h = html2text.HTML2Text()
                h.ignore_links = False
                body = h.handle(html_content)
            
            email_key = f"{from_header}:{subject}"
            if email_key in self.email_cache and self.email_cache[email_key] != "processing":
                analysis_result = self.email_cache[email_key]
            else:
                analysis_result = self.analyze_email(from_header, subject, body)
                self.email_cache[email_key] = analysis_result
            
            email_data = {
                'id': email_id.decode('utf-8'),
                'sender': from_header,
                'subject': subject,
                'date': date_str,
                'body': body,
                'original_html': html_content,
                'analysis': analysis_result
            }
            self.emails.append(email_data)
            
            status_icon = "✓" if analysis_result['is_safe'] else "✗"
            self.root.after(0, lambda: self.insert_one_email(email_data, status_icon))
        except Exception as e:
            print(f"Error processing email: {e}")
    
    def insert_one_email(self, email_data, status_icon):
        existing_ids = set()
        for item in self.email_tree.get_children():
            vals = self.email_tree.item(item, "values")
            if len(vals) == 5:
                existing_ids.add(vals[4])
        
        if email_data['id'] not in existing_ids:
            self.email_tree.insert("", 0, values=(
                email_data['sender'],
                email_data['subject'],
                email_data['date'],
                status_icon,
                email_data['id']
            ))
    
    def analyze_email(self, sender, subject, body):
        try:
            display_name, email_address = parseaddr(sender)
            sender_domain = ""
            if "@" in email_address:
                sender_domain = email_address.split("@")[1].lower()
            
            truncated_body = body[:500]
            link_domains = re.findall(r'https?://(?:www\.)?([^/\s]+)', truncated_body)
            link_domains = list(set([domain.lower() for domain in link_domains]))
            link_domains_str = ", ".join(link_domains) if link_domains else "None"
            legitimate_examples = (
                "Legitimate emails often originate from domains that match the sender's organization "
                "or well-known services like gmail.com, yahoo.com, or outlook.com. "
                "Examples: support@paypal.com, no-reply@amazon.com, notifications@twitter.com."
            )
            analysis_prompt = f"""
Please analyze this email for signs of phishing or scam:

Sender Display Name: {display_name if display_name else "N/A"}
Sender Email Address: {email_address}
Sender Domain: {sender_domain if sender_domain else "N/A"}
Subject: {subject}
Body (truncated): {truncated_body}

Link Domains in Body: {link_domains_str}

Context:
- {legitimate_examples}
- Check if the domains in any links mismatch the sender's domain.
- Recognize known legitimate service emails.
- Consider common legitimate email patterns.
- Rate the email's phishing likelihood on a scale of 1-10, where 1 is completely safe and 10 is definitely phishing.
- Explain your reasoning in at most 3 short bullet points.
Return your analysis in JSON format with these fields:
- phishing_score: (number between 1 and 10)
- is_safe: (boolean, true if score < 5)
- reasoning: (array of strings, max 3 items, each less than 80 chars)
"""
            response = self.openai_client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {
                        "role": "system", 
                        "content": (
                            "You are a cybersecurity expert specializing in email phishing detection. "
                            "Consider the sender's domain, display name, and link domains when evaluating the email."
                        )
                    },
                    {"role": "user", "content": analysis_prompt}
                ],
            )
            result_text = response.choices[0].message.content.strip()
            json_match = re.search(r'(\{.*\})', result_text, re.DOTALL)
            if json_match:
                result_text = json_match.group(1)
            try:
                result = json.loads(result_text)
            except json.JSONDecodeError:
                print(f"Failed to parse JSON: {result_text}")
                result = {
                    'phishing_score': 5.0,
                    'is_safe': False,
                    'reasoning': ["Could not parse AI response", "Treating as suspicious by default"]
                }
            return result
        except Exception as e:
            print(f"Error during analysis: {e}")
            return {
                'phishing_score': 5.0,
                'is_safe': False,
                'reasoning': [f"Error analyzing email: {str(e)}"]
            }
    
    def show_email_details(self, event):
        try:
            selected_items = self.email_tree.selection()
            if not selected_items:
                return
            selected_item = selected_items[0]
            values = self.email_tree.item(selected_item, 'values')
            if not values or len(values) < 5:
                return
            email_id = values[4]
            
            email_data = None
            for em in self.emails:
                if em['id'] == email_id:
                    email_data = em
                    break
            if not email_data:
                return
            
            if HAVE_TKINTERWEB:
                self.email_details.load_html(email_data.get('original_html', ''))
            else:
                self.email_details.delete(1.0, tk.END)
                self.email_details.insert(tk.END, f"From: {email_data['sender']}\n")
                self.email_details.insert(tk.END, f"Subject: {email_data['subject']}\n")
                self.email_details.insert(tk.END, f"Date: {email_data['date']}\n\n")
                self.email_details.insert(tk.END, f"Body:\n{email_data['body']}")
            
            self.analysis_text.delete(1.0, tk.END)
            score = email_data['analysis'].get('phishing_score', 5.0)
            is_safe = email_data['analysis'].get('is_safe', False)
            reasoning = email_data['analysis'].get('reasoning', [])
            safety_status = "✓ SAFE" if is_safe else "✗ POTENTIAL PHISHING"
            safety_color = "green" if is_safe else "red"
            
            self.analysis_text.insert(tk.END, f"Security Analysis: {safety_status}\n", safety_color)
            self.analysis_text.insert(tk.END, f"Phishing Score: {score:.1f} out of 10.0\n\n")
            self.analysis_text.insert(tk.END, "Reasoning:\n")
            for reason in reasoning:
                bullet = "• " if is_safe else "⚠ "
                self.analysis_text.insert(tk.END, f"{bullet}{reason}\n")
            
            self.analysis_text.tag_configure("green", foreground="green", font=("Helvetica", 10, "bold"))
            self.analysis_text.tag_configure("red", foreground="red", font=("Helvetica", 10, "bold"))
        
        except Exception as e:
            print(f"Error showing email details: {e}")
    
    def view_html(self):
        selected_items = self.email_tree.selection()
        if not selected_items:
            return
        selected_item = selected_items[0]
        values = self.email_tree.item(selected_item, 'values')
        if not values or len(values) < 5:
            return
        email_id = values[4]
        for email_data in self.emails:
            if email_data['id'] == email_id and 'original_html' in email_data:
                with open("temp_email.html", "w", encoding="utf-8") as f:
                    f.write(email_data['original_html'])
                webbrowser.open("file://" + os.path.abspath("temp_email.html"))
                break
    
    def run(self):
        self.root.mainloop()
        if self.imap_connection:
            self.is_polling = False
            try:
                self.imap_connection.logout()
            except:
                pass
        self.executor.shutdown(wait=False)
    
    def change_profile(self):
        """
        Allows the user to pick a different profile from the Netflix-style screen again.
        We first disconnect if connected, then show the ProfileManager.
        """
        if self.imap_connection:
            self.disconnect()
        
        self.root.withdraw()
        profile_window = tk.Toplevel(self.root)
        profile_manager = ProfileManager(profile_window)
        profile_window.wait_window()
        
        # If user selected a profile, update and reconnect
        if profile_manager.selected_profile:
            self.profile = profile_manager.selected_profile
            self.email_account = self.profile["email"]
            self.email_password = self.profile["password"]
            self.openai_api_key = self.profile["openai_api_key"]
            
            # Update the label in top_frame to show the new profile name
            for widget in self.root.winfo_children():
                if isinstance(widget, ttk.Frame):
                    for sub in widget.winfo_children():
                        if isinstance(sub, ttk.Label) and sub.cget("text").startswith("Profile:"):
                            sub.config(text=f"Profile: {self.profile['profile_name']}")
            
            self.root.deiconify()
            self.connect_to_email()
        else:
            messagebox.showinfo("Info", "No profile selected. Keeping old profile.")
            self.root.deiconify()

###################
# Application Run #
###################
def main():
    # Create a single Tk instance.
    root = tk.Tk()
    root.withdraw()  # Hide the main window during profile selection
    
    # Create a Toplevel for profile selection.
    profile_window = tk.Toplevel(root)
    profile_manager = ProfileManager(profile_window)
    profile_window.wait_window()  # Wait until the profile selection is complete
    
    if profile_manager.selected_profile:
        root.deiconify()  # Show the main window
        app = PhishingDetector(profile_manager.selected_profile, root)
        app.run()
    else:
        messagebox.showinfo("Info", "No profile selected. Exiting.")
        root.destroy()

if __name__ == "__main__":
    main()
