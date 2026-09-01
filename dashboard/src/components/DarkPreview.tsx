export function DarkPreview() {
  return (
    <div class="card">
      <h2 class="card-title">Dark list</h2>
      <div class="dark-preview">
        <p>
          The full dark list — request hashes, IPs, reasons and request samples — is private and
          only visible in <strong>Developer Mode</strong> on the owner's PC. The dashboard shows
          summary statistics only.
        </p>
        <a class="btn" href="http://localhost:8788" target="_blank" rel="noreferrer">
          Open Developer Mode →
        </a>
      </div>
    </div>
  );
}
