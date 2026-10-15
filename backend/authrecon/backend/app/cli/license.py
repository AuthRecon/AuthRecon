"""
CLI commands for license management

Usage:
    python -m app.cli.license activate LICENSE-KEY
    python -m app.cli.license status
    python -m app.cli.license check
    python -m app.cli.license deactivate
    python -m app.cli.license install-id
"""
import sys
import argparse
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services.license_client import (
    activate_license,
    check_license,
    deactivate_license,
    get_license_info,
    generate_installation_id,
    LICENSE_VALIDATION_ENABLED,
    LicenseValidationError
)


def cmd_activate(args):
    """Activate a license key"""
    try:
        print(f"Activating AuthRecon license...")
        print(f"License key: {args.license_key[:20]}...")

        result = activate_license(args.license_key, hostname=args.hostname)

        if result.get("_fail_safe_mode"):
            print("\n⚠️  LICENSE VALIDATION IS DISABLED (FAIL-SAFE MODE)")
            print("   This is a development/testing mode.")
            print("   Set LICENSE_VALIDATION_ENABLED=true in production.\n")

        print("\n✅ License activated successfully!\n")
        print(f"License Type:     {result['license_type'].title()}")
        print(f"Expires:          {datetime.fromisoformat(result['expires_at']).strftime('%B %d, %Y')}")

        print("\nFeatures:")
        for feature, enabled in result['features'].items():
            status = "✓" if enabled else "✗"
            print(f"  {status} {feature.replace('_', ' ').title()}")

        if not result.get("_fail_safe_mode"):
            print(f"\nNext license check: {datetime.fromisoformat(result['next_check_in']).strftime('%B %d, %Y')}")
            print(f"Grace period: {result['grace_period_days']} days")

        print("\nAuthRecon is ready to use. Run 'authrecon --help' to get started.")

    except LicenseValidationError as e:
        print(f"\n❌ License activation failed:\n   {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error:\n   {e}\n")
        sys.exit(1)


def cmd_status(args):
    """Show license status"""
    try:
        info = get_license_info()

        if info.get("_fail_safe_mode"):
            print("\n⚠️  LICENSE VALIDATION IS DISABLED (FAIL-SAFE MODE)")
            print("   All features are available in development mode.")
            print("   Set LICENSE_VALIDATION_ENABLED=true to enable license validation.\n")
            return

        if not info.get("valid"):
            print(f"\n❌ {info.get('message')}\n")
            sys.exit(1)

        print("\n✅ License Status: Active\n")
        print(f"License Type:     {info['license_type'].title()}")
        print(f"Expires:          {datetime.fromisoformat(info['expires_at']).strftime('%B %d, %Y')}")
        print(f"Last Validated:   {datetime.fromisoformat(info['last_validated']).strftime('%B %d, %Y %H:%M:%S UTC')}")

        print("\nFeatures:")
        for feature, enabled in info['features'].items():
            status = "✓" if enabled else "✗"
            print(f"  {status} {feature.replace('_', ' ').title()}")

        print()

    except Exception as e:
        print(f"\n❌ Error getting license status:\n   {e}\n")
        sys.exit(1)


def cmd_check(args):
    """Perform license validation check"""
    try:
        print("Checking license with server...")

        result = check_license()

        if result.get("_fail_safe_mode"):
            print("\n⚠️  License validation is disabled (fail-safe mode)\n")
            return

        if result.get("_cached"):
            print(f"\n✅ License valid (cached)")
            print(f"   Grace period remaining: {result['grace_remaining_days']} days")
            print(f"   Next online check due in {result['grace_remaining_days']} days\n")
        elif result.get("_grace_mode"):
            print(f"\n⚠️  License validation failed but within grace period")
            print(f"   Grace period remaining: {result['grace_remaining_days']} days")
            print(f"   Please check your internet connection\n")
        else:
            print(f"\n✅ License validated successfully")
            print(f"   Expires: {datetime.fromisoformat(result['expires_at']).strftime('%B %d, %Y')}")
            print(f"   {result.get('message', '')}\n")

    except LicenseValidationError as e:
        print(f"\n❌ License validation failed:\n   {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error:\n   {e}\n")
        sys.exit(1)


def cmd_deactivate(args):
    """Deactivate license on this machine"""
    try:
        if not args.yes:
            response = input("\nAre you sure you want to deactivate this license? (yes/no): ")
            if response.lower() not in ["yes", "y"]:
                print("Deactivation cancelled.")
                return

        print("Deactivating license...")

        result = deactivate_license()

        if result.get("_fail_safe_mode"):
            print("\n⚠️  License validation is disabled (fail-safe mode)")
            print("   Local license file removed.\n")
        else:
            print("\n✅ License deactivated successfully")
            print("   You can now activate this license on another machine.\n")

    except LicenseValidationError as e:
        print(f"\n❌ Deactivation failed:\n   {e}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error:\n   {e}\n")
        sys.exit(1)


def cmd_install_id(args):
    """Show installation ID"""
    installation_id = generate_installation_id()
    print(f"\nInstallation ID: {installation_id}\n")
    print("Use this ID when requesting offline licenses for air-gapped deployments.\n")


def main():
    parser = argparse.ArgumentParser(
        description="AuthRecon License Management",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest="command", help="License commands")

    # Activate command
    activate_parser = subparsers.add_parser("activate", help="Activate a license key")
    activate_parser.add_argument("license_key", help="License key to activate")
    activate_parser.add_argument("--hostname", help="Optional hostname for tracking")
    activate_parser.set_defaults(func=cmd_activate)

    # Status command
    status_parser = subparsers.add_parser("status", help="Show license status")
    status_parser.set_defaults(func=cmd_status)

    # Check command
    check_parser = subparsers.add_parser("check", help="Perform license validation check")
    check_parser.set_defaults(func=cmd_check)

    # Deactivate command
    deactivate_parser = subparsers.add_parser("deactivate", help="Deactivate license on this machine")
    deactivate_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    deactivate_parser.set_defaults(func=cmd_deactivate)

    # Install ID command
    install_id_parser = subparsers.add_parser("install-id", help="Show installation ID")
    install_id_parser.set_defaults(func=cmd_install_id)

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Show fail-safe mode warning if enabled
    if not LICENSE_VALIDATION_ENABLED and args.command not in ["install-id"]:
        print("\n" + "=" * 70)
        print("⚠️  LICENSE VALIDATION IS CURRENTLY DISABLED (FAIL-SAFE MODE)")
        print("=" * 70)
        print("License checking will work, but validation is not enforced.")
        print("To enable license validation, set: LICENSE_VALIDATION_ENABLED=true")
        print("=" * 70 + "\n")

    args.func(args)


if __name__ == "__main__":
    main()
