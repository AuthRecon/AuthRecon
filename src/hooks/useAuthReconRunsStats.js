import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import authreconApi from '../services/authreconApi'

const fetchRuns = async () => {
  const response = await authreconApi.get('runs')
  return Array.isArray(response.data) ? response.data : []
}

const dayMs = 24 * 60 * 60 * 1000

const computeMetrics = (runs) => {
  const safeRuns = Array.isArray(runs) ? runs : []
  const now = Date.now()
  const last24hCutoff = now - dayMs
  const last7dCutoff = now - dayMs * 7

  const baseSeries = Array.from({ length: 7 }).map((_, index) => {
    const dayOffset = 6 - index
    const date = new Date(now - dayOffset * dayMs)
    const key = date.toISOString().slice(0, 10)
    return {
      key,
      date,
      label: date.toLocaleDateString(undefined, { weekday: 'short' }),
      total: 0,
      succeeded: 0,
      failed: 0,
    }
  })

  const bucketIndex = baseSeries.reduce((acc, bucket, idx) => {
    acc[bucket.key] = idx
    return acc
  }, {})

  let runs24h = 0
  let runs7d = 0
  let success24h = 0
  let fail24h = 0
  let totalSuccess = 0
  let queuedCount = 0
  let runningCount = 0

  safeRuns.forEach((run) => {
    const submittedTs = run?.submitted_at ? Date.parse(run.submitted_at) : null
    if (!submittedTs) return

    if (submittedTs >= last7dCutoff) runs7d += 1
    if (submittedTs >= last24hCutoff) {
      runs24h += 1
      if (run.status === 'succeeded') success24h += 1
      if (run.status === 'failed') fail24h += 1
    }

    if (run.status === 'succeeded') totalSuccess += 1
    if (run.status === 'queued') queuedCount += 1
    if (run.status === 'running') runningCount += 1

    const bucketKey = new Date(submittedTs).toISOString().slice(0, 10)
    const index = bucketIndex[bucketKey]
    if (index !== undefined) {
      baseSeries[index].total += 1
      if (run.status === 'succeeded') baseSeries[index].succeeded += 1
      if (run.status === 'failed') baseSeries[index].failed += 1
    }
  })

  const successRate24h = runs24h ? Math.round((success24h / runs24h) * 100) : null
  const successRateAll = safeRuns.length ? Math.round((totalSuccess / safeRuns.length) * 100) : null

  return {
    totalRuns: safeRuns.length,
    last24hCount: runs24h,
    last7dCount: runs7d,
    successRate24h,
    successRateAll,
    failureCount24h: fail24h,
    queuedCount,
    runningCount,
    activeCount: queuedCount + runningCount,
    latestRun: safeRuns[0] || null,
    series: baseSeries,
    hasData: safeRuns.length > 0,
  }
}

function useAuthReconRunsStats(options = {}) {
  const query = useQuery({
    queryKey: ['authrecon', 'runs', 'dashboard'],
    queryFn: fetchRuns,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
    ...options,
  })

  const metrics = useMemo(() => computeMetrics(query.data || []), [query.data])

  return {
    ...query,
    metrics,
  }
}

export default useAuthReconRunsStats
