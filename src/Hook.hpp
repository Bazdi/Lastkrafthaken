#pragma once

#include <stdexcept>

#include <MinHook.h>

#define LKH_DEFINE_HOOK(return_type, calling_cv, name, args) \
	typedef return_type (calling_cv* lkh_fn_##name) args; \
	lkh_fn_##name lkh_orig_##name; \
	return_type calling_cv lkh_hk_##name args

#define LKH_CREATE_ADDR_HOOK(name, address) \
	lkh_orig_##name = (lkh_fn_##name)address; \
	if (!lkh::Hook::create(lkh_orig_##name, &lkh_hk_##name, &lkh_orig_##name)) { \
		printf("Lastkrafthaken> Failed to hook %s\n", #name); \
	}

#define LKH_CREATE_HOOK(name) \
	if (!lkh::Hook::create(&name, &lkh_hk_##name, &lkh_orig_##name)) { \
		printf("Lastkrafthaken> Failed to hook %s\n", #name); \
	}

#define LKH_REMOVE_HOOK(name) \
	if (!lkh::Hook::remove(&name, &lkh_hk_##name, &lkh_orig_##name)) { \
		printf("Lastkrafthaken> Failed to unhook %s\n", #name); \
	}

namespace lkh {
	class Hook {
	public:
		Hook(void* target, void* detour, void* original) : _target(target) {
			if (!create(target, detour, (void**)original)) {
				throw std::runtime_error("Failed to create hook");
			}

			if (!enable(target)) {
				throw std::runtime_error("Failed to enable hook");
			}
		}

		~Hook() {
			disable(_target);
		}

		static bool initialize() {
			return MH_Initialize() == MH_OK;
		}

		static bool uninitialize() {
			return MH_Uninitialize() == MH_OK;
		}

		static bool create(void* target, void* detour, void* original) {
			return MH_CreateHook(target, detour, (void**)original) == MH_OK;
		}

		static bool remove(void* target) {
			return MH_RemoveHook(target) == MH_OK;
		}

		static bool enable(void* target = MH_ALL_HOOKS) {
			return MH_EnableHook(target) == MH_OK;
		}

		static bool disable(void* target = MH_ALL_HOOKS) {
			return MH_DisableHook(target) == MH_OK;
		}

	private:
		void* _target;
	};
}