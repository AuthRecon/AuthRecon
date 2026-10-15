import React, { forwardRef } from 'react'

/**
 * Input Component
 * Text input with validation states
 */
const Input = forwardRef(({
  label,
  error,
  helperText,
  icon: Icon,
  className = '',
  ...props
}, ref) => {
  return (
    <div className="w-full">
      {label && (
        <label className="block text-sm font-medium text-slate-300 mb-2">
          {label}
          {props.required && <span className="text-rose-400 ml-1">*</span>}
        </label>
      )}

      <div className="relative">
        {Icon && (
          <div className="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none">
            <Icon className="w-5 h-5 text-slate-400" />
          </div>
        )}

        <input
          ref={ref}
          className={`
            input-field w-full px-4 py-2.5
            placeholder:text-slate-500
            focus:outline-hidden
            disabled:opacity-50 disabled:cursor-not-allowed
            ${Icon ? 'pl-11' : ''}
            ${className}
          `}
          style={error ? { borderColor: '#ff5f73' } : undefined}
          {...props}
        />
      </div>

      {error && (
        <p className="mt-1.5 text-sm text-rose-400">{error}</p>
      )}

      {!error && helperText && (
        <p className="mt-1.5 text-sm text-slate-500">{helperText}</p>
      )}
    </div>
  )
})

Input.displayName = 'Input'

export default Input
