#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <kthook/kthook.hpp>

#include <ios>
#include <fstream>

inline kthook::kthook_simple<void (*)()> CTimer_Update_hook;

inline bool is_model_available(int id) {
  return reinterpret_cast<void*(*)(int id)>(0x403DA0)(id) != nullptr;
}

void CTimer_Update(const decltype(CTimer_Update_hook) &hook) {
  if (GetAsyncKeyState(VK_END) & 0x8000) {
    std::ofstream file("free_pool_ids.txt", std::ios::trunc);
    std::vector<uint32_t> entries;
    entries.reserve(2000);
    static constexpr auto kItemsCount = 20000;
    for (auto i = 0; i < kItemsCount; i++) {
      if (!is_model_available(i)) { // if pool is free
        entries.emplace_back(i);
        if (i < kItemsCount - 1) continue;
      }
      if (!entries.empty()) { // pool is already used
        file << entries.front() << "-" << entries.back() << " > " << entries.size() << std::endl;
        entries.clear();
      }
    }
  }
  return hook.call_trampoline();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD fdwReason, LPVOID lpReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    CTimer_Update_hook.set_cb(CTimer_Update);
    CTimer_Update_hook.set_dest(0x53E968);
    CTimer_Update_hook.install();
  }
  return TRUE;
}
