import React from 'react'
import Card from '../../../../components/Card'
import RoleCard from './RoleCard'

function RoleSection({ runId, roles }) {
  if (!roles || roles.length === 0) {
    return null // Don't show section if no roles
  }

  const roleLabel = roles.length === 1 ? 'persona' : 'personas'

  return (
    <Card padding="lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-slate-50">
          Roles
        </h3>
        <span className="text-sm text-slate-500">
          {roles.length} {roleLabel} tested
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {roles.map((role, index) => (
          <RoleCard
            key={role.slug || role.username || role.label || index}
            runId={runId}
            role={role}
          />
        ))}
      </div>
    </Card>
  )
}

export default RoleSection
