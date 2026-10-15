import React from 'react'

/**
 * Badge Component
 * Status indicator pill
 */
function Badge({
  children,
  variant = 'default',
  size = 'md',
  dot = false,
  className = '',
}) {
  const sizeClasses = {
    sm: 'text-xs',
    md: 'text-xs',
    lg: 'text-sm',
  }

  const variantClasses = {
    default: '',
    success: 'success',
    error: 'fail',
    warning: 'warning',
    info: 'info',
    sky: 'form_based',
  }

  return (
    <span
      className={`chip inline-flex items-center gap-1.5 ${variantClasses[variant] ? variantClasses[variant] : ''} ${sizeClasses[size]} ${className}`.trim()}
    >
      {dot && (
        <span className="w-1.5 h-1.5 rounded-full bg-white/60" />
      )}
      {children}
    </span>
  )
}

export default Badge
