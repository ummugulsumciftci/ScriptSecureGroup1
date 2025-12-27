import docker
import time
import os

class ScriptSecureFinalSystem:
    def __init__(self, pool_size=2):
        self.client = docker.from_env()
        self.pool_size = pool_size
        self.pool = []
        self.stats = {"total": 0, "success": 0, "blocked": 0, "total_time": 0}
        self._initialize_pool()

    def _initialize_pool(self):
        print("--- [FAZ 2] Güvenli Altyapı Kuruluyor... ---")
        wrapper_path = os.path.abspath("./src/wrappers")
        for i in range(self.pool_size):
            c = self.client.containers.run(
                image="script-secure-base",
                command="tail -f /dev/null",
                detach=True,
                network_disabled=True,
                mem_limit="64m",
                pids_limit=15,               # [FAZ 4] Fork Bomb Koruması
                read_only=True,              # [FAZ 2] Salt Okunur FS
                tmpfs={'/tmp': 'size=16m'},  # [FAZ 4] RAM Disk Yazma
                cap_drop=["ALL"],            # [FAZ 2] En Az Ayrıcalık
                volumes={wrapper_path: {'bind': '/app/wrappers', 'mode': 'ro'}},
                remove=True
            )
            self.pool.append(c)
        print("✅ Sistem Çalışmaya Hazır.")

    def run_secure_script(self, code):
        self.stats["total"] += 1
        container = self.pool[0]
        start = time.time()
        
        # Kodun çalıştırılması
        full_cmd = f"import sys; sys.path.append('/app/wrappers'); {code}"
        result = container.exec_run(f"python3 -c \"{full_cmd}\"")
        
        duration = (time.time() - start) * 1000
        self.stats["total_time"] += duration

        # Logların Çıkarılması (Faz 3 Entegrasyonu)
        log_data = container.exec_run("cat /tmp/access.log").output.decode()
        
        # DÜZELTİLEN YER: returncode yerine exit_code kullanıyoruz
        if result.exit_code == 0:
            self.stats["success"] += 1
        else:
            self.stats["blocked"] += 1

        self._display_dashboard(duration, result.output.decode().strip())
        return log_data

    def _display_dashboard(self, last_time, last_out):
        os.system('cls' if os.name == 'nt' else 'clear')
        avg_time = self.stats["total_time"] / self.stats["total"]
        print("="*50)
        print("🛡️  SCRIPTSECURE CANLI İZLEME PANELİ (Phase 5)")
        print("="*50)
        print(f"📊 Toplam İstek: {self.stats['total']} | ✅ Başarı: {self.stats['success']} | 🚫 Engellenen: {self.stats['blocked']}")
        print(f"⏱️  Son Çalışma: {last_time:.2f} ms | ⚡ Ortalama: {avg_time:.2f} ms")
        print("-" * 50)
        print(f"📝 Son Çıktı: {last_out[:50]}...")
        print("="*50)

    def cleanup(self):
        for c in self.pool: c.kill()

if __name__ == "__main__":
    system = ScriptSecureFinalSystem(pool_size=1)
    try:
        # Örnek Çalıştırmalar
        system.run_secure_script("print('Sistem Stabil')")
        time.sleep(1)
        system.run_secure_script("open('/etc/shadow', 'r')") # Engellenecek
        time.sleep(1)
        system.run_secure_script("print('Hız Testi')")
    finally:
        system.cleanup()