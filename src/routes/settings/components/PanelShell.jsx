import React from 'react'
import Card from '../../../components/Card'

function PanelShell({ eyebrow, title, description, children, actions }) {
  return (
    <Card padding="lg" className="space-y-6">
      <header>
        <p className="text-xs uppercase tracking-wider text-slate-500">{eyebrow}</p>
        <div className="flex flex-wrap items-start gap-4 justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-50">{title}</h2>
            {description && (
              <p className="text-sm text-slate-400 mt-1">{description}</p>
            )}
          </div>
          {actions}
        </div>
      </header>
      {children}
    </Card>
  )
}

export default PanelShell
