import re
import smtplib
import logging
from email.mime.text import MIMEText
from collections import Counter
import os
from datetime import datetime

class SecurityAnalyzer:
    def __init__(self, log_file, alert_email=None, smtp_server='localhost', login_threshold=5, log_to_file=False):
        """
        Initialize the SecurityAnalyzer with necessary configurations.

        :param log_file: Path to the log file to analyze
        :param alert_email: Email address to send alerts to
        :param smtp_server: SMTP server for sending emails
        :param login_threshold: Number of failed login attempts to flag as suspicious
        :param log_to_file: Whether to log to a file or console
        """
        self.log_file = log_file
        self.alert_email = alert_email
        self.smtp_server = smtp_server
        self.login_threshold = login_threshold
        self.threats = []
        self.log_data = self._read_log_file()

        # Pre-compile regex patterns for efficiency
        self.suspicious_patterns = [
            re.compile(r'Failed password for invalid user'),
            re.compile(r'Accepted publickey for'),
            re.compile(r'Connection closed by'),
            re.compile(r'Unexpected file operation'),
            re.compile(r'Suspicious network traffic')
        ]

        self.malware_patterns = [
            re.compile(r'Unexpected file operation on .*\.exe'),
            re.compile(r'New network connection to unknown host')
        ]

        self._configure_logging(log_to_file)

    def _configure_logging(self, log_to_file):
        """Configure logging settings."""
        log_format = "%(asctime)s - %(levelname)s - %(message)s"
        logging.basicConfig(filename='security_analyzer.log' if log_to_file else None, 
                            level=logging.INFO, format=log_format)
        logging.info("SecurityAnalyzer initialized.")

    def _read_log_file(self):
        """Read the log file content."""
        if not os.path.exists(self.log_file):
            raise FileNotFoundError(f"Log file {self.log_file} does not exist.")
        with open(self.log_file, 'r') as file:
            return file.read()

    def _validate_email(self):
        """Validate email format."""
        if not re.match(r"[^@]+@[^@]+\.[^@]+", self.alert_email):
            raise ValueError(f"Invalid email format: {self.alert_email}")

    def parse_log(self):
        """Parse log for suspicious activities."""
        for line in self.log_data.splitlines():
            for pattern in self.suspicious_patterns:
                if pattern.search(line):
                    self.threats.append(f"Suspicious activity detected: {line.strip()}")
                    break

    def analyze_login_attempts(self):
        """Analyze login attempts for suspicious patterns."""
        login_pattern = re.compile(r'Failed password for (.*?) from')
        login_attempts = Counter(login_pattern.findall(self.log_data))
        for user, count in login_attempts.items():
            if count > self.login_threshold:
                self.threats.append(f"User {user} had {count} failed login attempts")

    def check_for_malware(self):
        """Check for potential malware activities."""
        for line in self.log_data.splitlines():
            for pattern in self.malware_patterns:
                if pattern.search(line):
                    self.threats.append(f"Potential Malware Activity: {line.strip()}")
                    break

    def send_alert(self):
        """Send an email alert if threats are detected."""
        if not self.alert_email or not self.threats:
            return
        
        self._validate_email()

        msg = MIMEText("\n".join(self.threats))
        msg['Subject'] = f'Security Alert - {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'
        msg['From'] = 'security@example.com'
        msg['To'] = self.alert_email

        with smtplib.SMTP(self.smtp_server) as server:
            server.send_message(msg)

    def run_analysis(self):
        """Run all security analysis methods."""
        self.parse_log()
        self.analyze_login_attempts()
        self.check_for_malware()

        if self.threats:
            self.send_alert()
            print("Security threats detected. An alert has been sent.")
        else:
            print("No significant security threats detected.")

# Usage
if __name__ == "__main__":
    analyzer = SecurityAnalyzer(
        log_file='/path/to/your/logfile.log',
        alert_email='your@email.com',
        smtp_server='localhost',
        login_threshold=5,
        log_to_file=True
    )
    analyzer.run_analysis()
