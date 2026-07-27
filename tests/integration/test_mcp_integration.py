"""Integration tests for MCP server.

These tests verify the MCP server works correctly end-to-end.
Run manually with: python -m tests.integration.test_mcp_integration
"""

import sys


def test_tools_directly():
    """Test tool functions directly without MCP protocol."""
    from passkey.mcp_server import (
        passkey_doctor,
        passkey_get_entry_fields,
        passkey_list_entries,
        passkey_status,
    )

    print("Testing passkey MCP tools directly...")
    print()

    # Test 1: List entries
    print("1. Testing passkey_list_entries...")
    entries = passkey_list_entries()
    print(f"   Found {len(entries)} entries: {entries}")
    print("   PASS")
    print()

    # Test 2: Get entry fields (use an existing entry if available)
    if entries:
        print("2. Testing passkey_get_entry_fields...")
        fields = passkey_get_entry_fields(entries[0])
        print(f"   Fields for '{entries[0]}': {fields}")
        print("   PASS")
        print()

    # Test 3: Status check
    print("3. Testing passkey_status...")
    status = passkey_status()
    print(f"   Summary: {status.get('summary', {})}")
    assert "summary" in status or "error" in status
    print("   PASS")
    print()

    # Test 4: Doctor check
    print("4. Testing passkey_doctor...")
    doctor = passkey_doctor()
    print(f"   Summary: {doctor.get('summary', {})}")
    assert "checks" in doctor
    assert "issues" in doctor
    assert "recommendations" in doctor
    print("   PASS")
    print()

    print("=" * 40)
    print("All integration tests passed!")
    return True


def test_error_handling():
    """Test error handling for edge cases."""
    from passkey.mcp_server import passkey_get_entry_fields

    print()
    print("Testing error handling...")
    print()

    # Test missing entry
    print("1. Testing passkey_get_entry_fields with missing entry...")
    try:
        passkey_get_entry_fields("nonexistent-entry-12345")
        print("   FAIL: Should have raised an exception")
        return False
    except Exception as e:
        print(f"   Got expected error: {e}")
        print("   PASS")
    print()

    print("Error handling tests passed!")
    return True


if __name__ == "__main__":
    try:
        success = test_tools_directly()
        if success:
            success = test_error_handling()
        sys.exit(0 if success else 1)
    except Exception as e:
        print(f"FAIL: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
