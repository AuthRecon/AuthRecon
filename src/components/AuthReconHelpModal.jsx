import { X, CheckCircle2, AlertCircle, Info } from 'lucide-react';

export default function AuthReconHelpModal({ isOpen, onClose }) {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs p-4">
      <div className="bg-slate-900 border border-slate-800/80 rounded-2xl shadow-2xl w-full max-w-3xl max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-slate-900 border-b border-slate-800/80 px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-50">AuthRecon Engine - Detection Guide</h2>
            <p className="text-sm text-slate-400 mt-0.5">What we detect, what we automate, and what to expect</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-6">
          {/* What We Can Detect & Automate */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <CheckCircle2 className="w-5 h-5 text-green-400" />
              <h3 className="text-lg font-semibold text-slate-50">What We Can Detect & Automate</h3>
            </div>
            <div className="space-y-3 text-sm text-slate-300">
              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ Basic Authentication</p>
                <p className="text-slate-400">HTTP Basic Auth with WWW-Authenticate headers. Full automation with credentials.</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ Form-Based Login</p>
                <p className="text-slate-400">Traditional username/password forms. Includes JavaScript-rendered forms (React, Vue, Angular).</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ Two-Step Forms</p>
                <p className="text-slate-400">Progressive disclosure logins (email first, then password). Common in enterprise applications.</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ Azure AD / Microsoft Login</p>
                <p className="text-slate-400">Microsoft enterprise SSO flows. Handles login.microsoftonline.com redirects.</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ Okta Hosted Login</p>
                <p className="text-slate-400">Okta SSO authentication. Supports Okta-hosted login pages.</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ LDAP / ADFS</p>
                <p className="text-slate-400">Active Directory Federation Services. Government and enterprise portals (e.g., sso.example.gov).</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ OAuth 2.0 / OpenID Connect</p>
                <p className="text-slate-400">"Sign in with Google/GitHub" flows. Supports Google, GitHub, LinkedIn, Auth0, AWS Cognito.</p>
              </div>

              <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">✅ SAML SSO</p>
                <p className="text-slate-400">SAML 2.0 redirects to an identity provider login page.</p>
              </div>

              <p className="text-xs text-slate-500">
                Form, two-step and Basic logins are tested end to end against LoginLab. The SSO handlers above are
                automated too, but test them against your own identity provider and use Verify before relying on the script.
              </p>
            </div>
          </section>

          {/* Detected, configured in WAS directly */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-5 h-5 text-blue-400" />
              <h3 className="text-lg font-semibold text-slate-50">Detected, Configured in WAS Directly</h3>
            </div>
            <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 text-sm text-slate-400 space-y-2">
              <p>
                <span className="font-medium text-slate-200">Windows Integrated (Kerberos/NTLM)</span> and{' '}
                <span className="font-medium text-slate-200">HTTP Digest</span> are handled by the browser, not by a login page,
                so there is no Selenium script to record. AuthRecon detects them and the run explains what to set instead:
                in Tenable WAS, choose the matching HTTP authentication type and enter the account there.
              </p>
            </div>
          </section>

          {/* Detection Confidence */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-5 h-5 text-blue-400" />
              <h3 className="text-lg font-semibold text-slate-50">Detection Confidence Scores</h3>
            </div>
            <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 space-y-2 text-sm text-slate-300">
              <p><span className="text-green-400 font-medium">90-100%:</span> Definitive signals (HTTP headers, known provider redirects)</p>
              <p><span className="text-blue-400 font-medium">80-89%:</span> Strong signals (complete forms, OAuth parameters)</p>
              <p><span className="text-yellow-400 font-medium">50-79%:</span> Moderate signals (partial forms, branding hints)</p>
              <p><span className="text-red-400 font-medium">Below 50%:</span> Low confidence (generic fallback)</p>
            </div>
          </section>

          {/* What We Can't Do */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <AlertCircle className="w-5 h-5 text-yellow-400" />
              <h3 className="text-lg font-semibold text-slate-50">Current Limitations</h3>
            </div>
            <div className="space-y-3 text-sm text-slate-300">
              <div className="bg-slate-800/40 border border-yellow-500/20 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">❌ CAPTCHA / Bot Detection</p>
                <p className="text-slate-400">Cannot bypass CAPTCHA, reCAPTCHA, or advanced bot detection systems.</p>
              </div>

              <div className="bg-slate-800/40 border border-yellow-500/20 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">❌ Multi-Factor Authentication (MFA)</p>
                <p className="text-slate-400">Cannot complete 2FA/MFA flows (SMS codes, authenticator apps, hardware tokens).</p>
              </div>

              <div className="bg-slate-800/40 border border-yellow-500/20 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">❌ Certificate-Based Authentication</p>
                <p className="text-slate-400">Cannot use client certificates or smart cards (detection only).</p>
              </div>

              <div className="bg-slate-800/40 border border-yellow-500/20 rounded-lg p-4">
                <p className="font-medium text-slate-200 mb-2">❌ WebAuthn / FIDO2</p>
                <p className="text-slate-400">Biometric or hardware key authentication not supported.</p>
              </div>
            </div>
          </section>

          {/* What to Expect */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-5 h-5 text-cyan-400" />
              <h3 className="text-lg font-semibold text-slate-50">What to Expect</h3>
            </div>
            <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 space-y-3 text-sm text-slate-300">
              <div>
                <p className="font-medium text-slate-200 mb-1">🔍 Detection Phase</p>
                <p className="text-slate-400">AuthRecon probes the target URL and common login paths (/login, /signin, etc.) to identify the authentication type. Plain HTTP checks are quick; pages that need JavaScript rendering take a few seconds longer.</p>
              </div>

              <div>
                <p className="font-medium text-slate-200 mb-1">🤖 Automation Phase</p>
                <p className="text-slate-400">For supported auth types, a headless Chrome browser automates the login flow with your credentials. This generates real screenshots, HAR files, and Selenium IDE scripts.</p>
              </div>

              <div>
                <p className="font-medium text-slate-200 mb-1">📦 Artifacts Generated</p>
                <p className="text-slate-400">Successful runs produce: screenshots (PNG), Selenium IDE script (.side), HAR network capture, and exports for Burp Suite, curl, Postman, and OWASP ZAP.</p>
              </div>

              <div>
                <p className="font-medium text-slate-200 mb-1">🎯 Tenable WAS Setup</p>
                <p className="text-slate-400">The run page opens with the values WAS needs: login page, page to verify, the pattern-to-verify regex and the .side script. Click <span className="text-cyan-400">Verify</span> to replay the script in a clean browser the way the scanner will (this counts as one more login on the account), then download the .side for your scan's Selenium authentication settings. Below it, <span className="text-cyan-400">Scan readiness</span> grades how well the login will scan and suggests starting scan settings (URLs to exclude, the session cookie, performance tweaks).</p>
              </div>
              <div>
                <p className="font-medium text-slate-200 mb-1">🩺 After a scan</p>
                <p className="text-slate-400">If a WAS scan failed or came back thin, upload its debug .zip or JSON export to the <span className="text-cyan-400">Scan Analyzer</span> (preview). It explains what went wrong and which settings to change.</p>
              </div>

              <div>
                <p className="font-medium text-slate-200 mb-1">⚠️ When Automation Fails</p>
                <p className="text-slate-400">If credentials are wrong, the site uses MFA, or CAPTCHA is present, automation will fail with screenshots showing the error state. This is intentional - we never fake success.</p>
              </div>
            </div>
          </section>

          {/* Tips */}
          <section>
            <div className="flex items-center gap-2 mb-4">
              <Info className="w-5 h-5 text-sky-400" />
              <h3 className="text-lg font-semibold text-slate-50">Pro Tips</h3>
            </div>
            <div className="bg-slate-800/40 border border-slate-700/50 rounded-lg p-4 space-y-2 text-sm text-slate-300">
              <p>• Use <span className="text-cyan-400 font-mono">Login Hint</span> when a page has multiple login buttons (e.g., "Sign in with Google" + "Email login")</p>
              <p>• Set <span className="text-cyan-400 font-mono">Domain Prefix</span> for LDAP/AD environments requiring DOMAIN\username format</p>
              <p>• Check confidence scores in results - scores below 80% may indicate uncertain detection</p>
              <p>• For JavaScript-heavy sites, detection may take a few seconds as the engine renders the page</p>
              <p>• Multi-role testing lets you test different user personas in one run (admin, user, guest)</p>
            </div>
          </section>
        </div>

        {/* Footer */}
        <div className="sticky bottom-0 bg-slate-900 border-t border-slate-800/80 px-6 py-4">
          <button
            onClick={onClose}
            className="w-full px-4 py-2.5 bg-[rgba(41,199,255,0.1)] border border-[rgba(41,199,255,0.3)] text-slate-50 rounded-xl hover:bg-[rgba(41,199,255,0.15)] transition-colors font-medium"
          >
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
