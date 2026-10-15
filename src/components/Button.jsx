import React from 'react'
import { Loader2 } from 'lucide-react'

/**
 * Button Component
 * Reusable button with multiple variants
 */
function Button({
  children,
  variant = 'primary',
  size = 'md',
  loading = false,
  disabled = false,
  icon: Icon,
  iconPosition = 'left',
  className = '',
  ...props
}) {
  const baseStyles = 'inline-flex items-center justify-center font-medium font-mono transition-all duration-150 rounded focus:outline-none focus:ring-1 focus:ring-[var(--accent-blue)] focus:ring-offset-1 focus:ring-offset-[var(--bg-0)] disabled:opacity-40 disabled:cursor-not-allowed'

  const variants = {
    primary: 'button-primary',
    secondary: 'button-neutral',
    danger: 'bg-rose-500 hover:bg-rose-600 text-white shadow-lg hover:shadow-rose-500/50 focus:ring-rose-500',
    ghost: 'bg-transparent hover:bg-white/5 text-[var(--text-secondary)] hover:text-white focus:ring-white/20',
    outline: 'border border-[var(--stroke-blue)] hover:border-[var(--accent-blue)] text-[var(--accent-blue)] focus:ring-[var(--accent-blue-soft)]',
  }

  const sizes = {
    sm: 'px-3 py-1.5 text-sm gap-1.5',
    md: 'px-4 py-2 text-sm gap-2',
    lg: 'px-6 py-3 text-base gap-2',
  }

  return (
    <button
      className={`${baseStyles} ${variants[variant]} ${sizes[size]} ${className}`}
      disabled={disabled || loading}
      {...props}
    >
      {loading && <Loader2 className="w-4 h-4 animate-spin" />}
      {!loading && Icon && iconPosition === 'left' && <Icon className="w-4 h-4" />}
      {children}
      {!loading && Icon && iconPosition === 'right' && <Icon className="w-4 h-4" />}
    </button>
  )
}

export default Button
