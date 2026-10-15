import React from 'react'
import MetricCard from './MetricCard'

function SummaryDashboard({ run, artifactCount = 0, screenshotCount = 0 }) {
  // Calculate duration
  let duration = '—'
  if (run.submitted_at && run.finished_at) {
    const start = new Date(run.submitted_at)
    const end = new Date(run.finished_at)
    const seconds = Math.round((end - start) / 1000)
    duration = `${seconds}s`
  }

  const roleCount = run.roles?.length || 1

  // Icons using Lucide-style SVG
  const iconProps = {
    fill: 'none',
    viewBox: '0 0 24 24',
    stroke: 'currentColor',
    strokeWidth: 1.75,
  }

  const globeIcon = (
    <svg {...iconProps}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s1.343-9 3-9m-9 9a9 9 0 019-9" />
    </svg>
  )

  const clockIcon = (
    <svg {...iconProps}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
    </svg>
  )

  const usersIcon = (
    <svg {...iconProps}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.354a4 4 0 110 5.292M15 21H3v-1a6 6 0 0112 0v1zm0 0h6v-1a6 6 0 00-9-5.197M13 7a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  )

  const fileIcon = (
    <svg {...iconProps}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M7 21h10a2 2 0 002-2V9.414a1 1 0 00-.293-.707l-5.414-5.414A1 1 0 0012.586 3H7a2 2 0 00-2 2v14a2 2 0 002 2z" />
    </svg>
  )

  const cameraIcon = (
    <svg {...iconProps}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 9a2 2 0 012-2h.93a2 2 0 001.664-.89l.812-1.22A2 2 0 0110.07 4h3.86a2 2 0 011.664.89l.812 1.22A2 2 0 0018.07 7H19a2 2 0 012 2v9a2 2 0 01-2 2H5a2 2 0 01-2-2V9z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 13a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  )

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
      <MetricCard
        label="Target URL"
        value={run.target_url}
        icon={globeIcon}
        allowWrap
      />
      <MetricCard
        label="Duration"
        value={duration}
        icon={clockIcon}
        sublabel={run.finished_at ? new Date(run.finished_at).toLocaleString() : 'In progress'}
      />
      <MetricCard
        label="Roles Tested"
        value={roleCount}
        icon={usersIcon}
      />
      <MetricCard
        label="Artifacts"
        value={artifactCount}
        icon={fileIcon}
      />
      <MetricCard
        label="Screenshots"
        value={screenshotCount}
        icon={cameraIcon}
      />
    </div>
  )
}

export default SummaryDashboard
