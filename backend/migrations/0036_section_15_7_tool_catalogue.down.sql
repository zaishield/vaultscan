DELETE FROM scanner_image_registry
 WHERE tool IN ('sqlmap','gobuster','dirsearch','semgrep','gitleaks','hydra','recon-ng');
