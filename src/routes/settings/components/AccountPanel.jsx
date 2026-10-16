import { useState } from 'react';
import { Link } from 'react-router-dom';
import { KeyRound, Lock } from 'lucide-react';
import PanelShell from './PanelShell';
import Badge from '../../../components/Badge';
import Button from '../../../components/Button';
import { PasswordChangeModal } from './PasswordChangeModal';
import { MfaPanel } from './MfaPanel';
import useAuthStore from '../../../store/authStore';
import { useChangeOwnPassword } from '../../../services/usePortalUsers';

function ReadOnlyField({ label, children }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">{label}</p>
      <div className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-200">
        {children}
      </div>
    </div>
  );
}

export function AccountPanel() {
  const user = useAuthStore((state) => state.user);
  const [isPasswordModalOpen, setIsPasswordModalOpen] = useState(false);
  const [successMessage, setSuccessMessage] = useState('');
  const changePasswordMutation = useChangeOwnPassword();

  const handlePasswordChange = async (payload) => {
    try {
      await changePasswordMutation.mutateAsync(payload);
      setSuccessMessage('Password changed.');
      setIsPasswordModalOpen(false);
      setTimeout(() => setSuccessMessage(''), 5000);
    } catch (error) {
      throw new Error(error.response?.data?.detail || 'Failed to change password');
    }
  };

  return (
    <div className="space-y-6">
      <PanelShell eyebrow="Account" title="Your profile" description="The account you sign in to AuthRecon with.">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <ReadOnlyField label="Username / email">{user?.username || 'Not available'}</ReadOnlyField>
          <ReadOnlyField label="Role">
            <Badge variant={user?.is_admin ? 'info' : 'default'}>{user?.is_admin ? 'Administrator' : 'Operator'}</Badge>
          </ReadOnlyField>
          {user?.full_name && <ReadOnlyField label="Full name">{user.full_name}</ReadOnlyField>}
        </div>
      </PanelShell>

      <PanelShell
        eyebrow="Security"
        title="Password"
        description="Change your password. Other sessions stay signed in until they expire or you sign them out."
        actions={
          <Button variant="outline" icon={Lock} onClick={() => setIsPasswordModalOpen(true)}>
            Change password
          </Button>
        }
      >
        {successMessage && <p className="text-sm text-emerald-400">{successMessage}</p>}
      </PanelShell>

      <MfaPanel />

      <PanelShell
        eyebrow="Access"
        title="API & MCP keys"
        description="Keys for the AuthRecon CLI and for AI clients (MCP) are managed in one place."
        actions={
          <Link to="/settings?tab=ai">
            <Button variant="outline" icon={KeyRound}>Manage keys</Button>
          </Link>
        }
      />

      <PasswordChangeModal
        isOpen={isPasswordModalOpen}
        onClose={() => setIsPasswordModalOpen(false)}
        onSubmit={handlePasswordChange}
        isLoading={changePasswordMutation.isPending}
      />
    </div>
  );
}
