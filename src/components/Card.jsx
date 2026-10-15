import React from 'react'

/**
 * Card Component
 * Reusable card container with variants
 */
function Card({
  children,
  variant = 'default',
  padding = 'md',
  hover = false,
  className = '',
  ...props
}) {
  const variants = {
    default: 'card',
    solid: 'bg-slate-800 border border-slate-700 rounded-3xl',
    outline: 'border-2 border-slate-700 rounded-3xl bg-transparent',
    gradient: 'bg-(--grad-card) border border-(--stroke-dark) rounded-(--radius-hard) shadow-(--shadow-card)',
  }

  const paddings = {
    none: '',
    sm: 'p-4',
    md: 'p-6',
    lg: 'p-8',
  }

  const hoverEffect = hover
    ? 'transition-all duration-200 hover:shadow-2xl hover:scale-[1.02] cursor-pointer'
    : ''

  return (
    <div
      className={`${variants[variant]} ${paddings[padding]} ${hoverEffect} ${className}`}
      {...props}
    >
      {children}
    </div>
  )
}

export default Card
