Please include:

- Detailed description of the issue
- Steps to reproduce
- Impact assessment if known
- Any suggested mitigations or fixes

**Do not** publicly disclose the vulnerability until a fix or mitigation has been released.

---

## Security Best Practices Implemented

- **User Authentication:**  
  Uses Flask-Login with password hashing via Werkzeug's `generate_password_hash` and `check_password_hash` for secure credential storage.

- **Rate Limiting:**  
  APIs are rate-limited using `Flask-Limiter` to mitigate brute force attacks and abuse.

- **Input Validation:**  
  Uploaded files are restricted by allowed file extensions and validated where applicable.

- **File Handling:**  
  Uploaded videos, images, and generated thumbnails are stored in designated directories with automatic cleanup of files older than 24 hours to minimize storage risks.

- **Session Management:**  
  Flask sessions are signed using a strong secret key. Ensure `app.secret_key` is set to a secure, unpredictable value in production.

- **Protection Against Common Vulnerabilities:**  
  The app uses Flask’s built-in protections against Cross-Site Request Forgery (CSRF) and Cross-Site Scripting (XSS) in templates. Avoid inserting untrusted inputs directly into templates or scripts.

---

## Security Recommendations for Users / Deployers

- **Use HTTPS**:  
  Deploy the app behind an HTTPS-enabled reverse proxy (e.g., Nginx with TLS certificates) to secure data in transit.

- **Keep Dependencies Updated:**  
  Regularly update Python packages to incorporate security patches.

- **Secure Configuration:**  
  - Use environment variables or secure vaults to manage secrets such as `SECRET_KEY` and database credentials.  
  - Do not commit secrets to source control.

- **Limit File Upload Sizes:**  
  Configure maximum upload sizes in both Flask and any proxy server to prevent denial-of-service attacks.

- **Restrict Access:**  
  Consider deploying behind firewalls or VPNs if sensitive data is processed.

- **Monitor and Audit:**  
  Maintain logs and monitor access patterns to detect suspicious activity.

---

## Known Security Limitations

- The application does not currently implement account lockouts after multiple failed login attempts.

- Uploaded videos and images are stored on the filesystem without encryption.

- Large-scale or public deployments should implement additional protections, such as virus scanning on uploads and more advanced authentication mechanisms (e.g., multi-factor authentication).

---

## Security Updates and Patch Policy

Security fixes will be prioritized by the project maintainers and released as soon as possible. Please ensure your deployment regularly updates to the latest version.

---

## Thank You

Thank you for using and contributing to the Person Finder in Video project. Your security is important to us.

---

*This Security Policy was last updated on 2025-11-20.*
