import BackButton from "@/app/back-button";

export default function PrivacyPolicyPage() {
  return (
    <div className="app-shell p-6">
      <div className="max-w-3xl mx-auto glass-panel p-6 space-y-4">
        <BackButton href="/" label="Back" />
        <h1 className="text-3xl font-bold">Privacy Policy</h1>
        <p className="section-subtitle">
          We store ticket details, scan history, and anti-fraud metadata only to
          operate event validation and safety for NUST societies and
          departments.
        </p>
        <ul className="list-disc ml-6 section-subtitle space-y-1">
          <li>
            Collected: holder name, role/department, ticket status, scan
            timestamps.
          </li>
          <li>
            Anti-fraud: device fingerprint and short-lived QR token validation.
          </li>
          <li>Access: only authorized event admins/staff.</li>
          <li>
            Retention: logs should be retained only as needed for event
            operations.
          </li>
        </ul>
        <p className="text-sm section-subtitle">
          Contact privacy@Riwaq.pk for data requests.
        </p>
      </div>
    </div>
  );
}
