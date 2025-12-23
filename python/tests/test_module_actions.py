"""Test module actions support for auxiliary/post modules."""

import pytest


@pytest.mark.asyncio
async def test_module_actions(client):
    """Test that module actions work correctly."""
    # Create an auxiliary module with actions
    # Using cisco_cucdm_call_forward which has Forward and Info actions
    module_id = await client.create_module("auxiliary/voip/cisco_cucdm_call_forward")

    try:
        # Get available actions
        actions = await client.module_actions(module_id)
        assert len(actions) > 0, "Module should have at least one action"
        assert "Forward" in actions, "Should have Forward action"
        assert "Info" in actions, "Should have Info action"
        print(f"✓ Found {len(actions)} actions: {actions}")

        # Get default action
        default_action = await client.module_default_action(module_id)
        assert default_action is not None, "Module should have a default action"
        assert default_action in actions, "Default action should be in actions list"
        print(f"✓ Default action: {default_action}")

        # Get current action (should be default initially)
        current_action = await client.module_action(module_id)
        assert current_action == default_action, "Initial action should be default"
        print(f"✓ Current action matches default: {current_action}")

        # Set a different action via datastore
        await client.module_set_option(module_id, "ACTION", "Forward")

        # Get current action again
        new_action = await client.module_action(module_id)
        assert new_action == "Forward", "Action should be updated to Forward"
        print(f"✓ Action updated via datastore: {new_action}")

    finally:
        await client.delete_module(module_id)


@pytest.mark.asyncio
async def test_module_without_actions(client):
    """Test that modules without actions return empty lists."""
    # Exploit modules don't have actions
    module_id = await client.create_module("exploit/unix/ftp/vsftpd_234_backdoor")

    try:
        # Get actions (should be empty for exploit modules)
        actions = await client.module_actions(module_id)
        assert isinstance(actions, list), "Should return a list"
        assert len(actions) == 0, "Exploit modules shouldn't have actions"

        # Default action should be None
        default_action = await client.module_default_action(module_id)
        assert default_action is None, "Exploit module shouldn't have default action"

        # Current action should be None
        current_action = await client.module_action(module_id)
        assert current_action is None, "Exploit module shouldn't have current action"

        print("✓ Exploit module correctly has no actions")

    finally:
        await client.delete_module(module_id)


@pytest.mark.asyncio
async def test_post_module_actions(client):
    """Test actions on post modules."""
    # Post modules can have actions - using webcam as example
    module_id = await client.create_module("post/windows/manage/webcam")

    try:
        # Get actions
        actions = await client.module_actions(module_id)
        assert len(actions) > 0, "Webcam post module should have actions"
        assert "LIST" in actions, "Should have LIST action"
        assert "SNAPSHOT" in actions, "Should have SNAPSHOT action"
        print(f"✓ Post module has {len(actions)} actions: {actions}")

        # Get default
        default_action = await client.module_default_action(module_id)
        assert default_action in actions, "Default should be in actions list"
        print(f"✓ Post module default action: {default_action}")

    finally:
        await client.delete_module(module_id)
