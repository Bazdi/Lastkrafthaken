#define _CRT_SECURE_NO_WARNINGS

#include "Pattern.hpp"
#include "Hook.hpp"

#include <cstdio>

namespace pattern {
    const char* ets2_bank_withdraw = "E8 ? ? ? ? 4C 8D 4D C7"; // first opcode
}

LKH_DEFINE_HOOK(__int64, __fastcall, ets2_bank_withdraw, (__int64 ets2_bank_ptr, __int64 withdraw_amount, char a3)) {
    printf("HOOK: ets2_bank_withdraw: bank_ptr=%lld a2=%lld a3=%ld\n", ets2_bank_ptr, withdraw_amount, a3);
    printf("  money=%lld withdraw_amount=%lld\n", *(uint64_t*)(ets2_bank_ptr + 16), withdraw_amount);

    return lkh_orig_ets2_bank_withdraw(ets2_bank_ptr, withdraw_amount, a3);
}

void lkh_main() {
    AllocConsole();
    freopen("CONOUT$", "w", stdout);

    auto ets2_bank_withdraw_addr = lkh::Pattern::find(pattern::ets2_bank_withdraw, true, 1);

    printf("Lastkrafthaken> Found ets2_bank_withdraw at 0x%08x\n", ets2_bank_withdraw_addr);

    if (!lkh::Hook::initialize()) {
        printf("Lastkrafthaken> Failed to initialize hooks\n");
        return;
    }

    LKH_CREATE_ADDR_HOOK(ets2_bank_withdraw, ets2_bank_withdraw_addr);

    if (!lkh::Hook::enable()) {
        printf("Lastkrafthaken> Failed to enable hooks\n");
        return;
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
            lkh_main();
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
        break;
    }

    return TRUE;
}

