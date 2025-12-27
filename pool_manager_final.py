import docker
import time
import os

class ScriptSecureFinalSystem:
    def __init__(self, pool_size=1):
        try:
            self.client = docker.from_env()
        except Exception as e:
            print(f"❌ Docker Hatası: {e}"); exit(1)
            
        self.pool_size = pool_size
        self.pool = []
        self.stats = {"total": 0, "success": 0, "blocked": 0, "total_time": 0}
        self._initialize_pool()

    def _initialize_pool(self):
        """Konteynerleri güvenli ve kararlı bir şekilde başlatır."""
        print("--- [FAZ 2 & 4] İzolasyon Katmanı Başlatılıyor... ---")
        wrapper_path = os.path.abspath("./src/wrappers")
        
        # Temizlik: Önceki denemelerden kalan artıkları temizle
        for c in self.client.containers.list(all=True, filters={"ancestor": "script-secure-base"}):
            try: c.remove(force=True)
            except: pass

        try:
            with open("seccomp_profile.json", "r") as f:
                seccomp_content = f.read()
        except:
            print("❌ Seccomp dosyası eksik!"); return

        for i in range(self.pool_size):
            try:
                container = self.client.containers.run(
                    image="script-secure-base",
                    command="/usr/bin/python3 -c 'import time; time.sleep(1000000)'",
                    detach=True,
                    network_disabled=True,
                    mem_limit="64m",
                    pids_limit=15,
                    cpu_quota=50000,
                    read_only=True,
                    tmpfs={'/tmp': 'size=16m'},
                    cap_drop=["ALL"],
                    security_opt=[f"seccomp={seccomp_content}"], 
                    volumes={wrapper_path: {'bind': '/app/wrappers', 'mode': 'ro'}},
                    remove=False # KRİTİK: Docker'ın bizden önce silmesini engelliyoruz
                )
                
                # Konteynerin durumunu doğrula
                time.sleep(0.7) # Docker'ın toparlanması için biraz daha süre
                try:
                    container.reload()
                    if container.status == "running":
                        self.pool.append(container)
                        print(f"✅ Konteyner {i+1} hazır.")
                    else:
                        print(f"⚠️ Konteyner {i+1} durdu: {container.logs().decode()}")
                except:
                    print(f"⚠️ Konteyner {i+1} doğrulanamadı.")
                    
            except Exception as e:
                print(f"❌ Başlatma hatası: {e}")
        
        if self.pool:
            print("🚀 SİSTEM ÇALIŞMAYA HAZIR.")

    def run_secure_script(self, code, lang="/usr/bin/python3"):
        if not self.pool: return "Hata: Havuz aktif değil."
        self.stats["total"] += 1
        container = self.pool[0]
        start = time.time()
        
        try:
            full_cmd = f"import sys; sys.path.append('/app/wrappers'); {code}"
            result = container.exec_run(f"{lang} -c \"{full_cmd}\"")
            output = result.output.decode().strip()
            
            if result.exit_code == 0:
                self.stats["success"] += 1
            else:
                self.stats["blocked"] += 1
                if not output: output = "🛡️ Güvenlik Kısıtlaması (Seccomp)"
        except Exception as e:
            output = f"⚠️ Çalışma Hatası: {str(e)[:40]}"
            self.stats["blocked"] += 1

        duration = (time.time() - start) * 1000
        self.stats["total_time"] += duration
        self._display_dashboard(duration, output)
        return output

    def _display_dashboard(self, last_time, last_out):
        os.system('cls' if os.name == 'nt' else 'clear')
        avg_time = self.stats["total_time"] / self.stats["total"]
        print("="*65)
        print("🛡️  SCRIPTSECURE: İZOLASYON VE PERFORMANS PANELİ")
        print("="*65)
        print(f"📊 Toplam İstek : {self.stats['total']} | ✅ Başarı: {self.stats['success']} | 🚫 Engellenen: {self.stats['blocked']}")
        print("-" * 65)
        print(f"⏱️  Son Çalışma  : {last_time:.2f} ms")
        print(f"⚡ Ortalama Hız  : {avg_time:.2f} ms")
        print(f"📉 Sistem Yükü  : ~{min(10, avg_time/10):.1f}%")
        print("-" * 65)
        print(f"📝 Son Çıktı    : {last_out[:60]}")
        print("="*65)

    def cleanup(self):
        print("\n🧹 Temizlik yapılıyor...")
        for c in self.pool:
            try: c.remove(force=True)
            except: pass

if __name__ == "__main__":
    sandbox = ScriptSecureFinalSystem(pool_size=1)
    try:
        sandbox.run_secure_script("print('Test 1: Sistem Hazir!')")
        time.sleep(2)
        sandbox.run_secure_script("open('/etc/shadow', 'r')") 
        time.sleep(2)
        sandbox.run_secure_script("print('Test 2: Performans OK')")
    except: pass
    finally: sandbox.cleanup()
