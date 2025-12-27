const { enableScriptSecureWrappers } = require('../Wrappers/Nodejs_Wrapper');

enableScriptSecureWrappers();

const fs = require('fs');
const child_process = require('child_process');
const net = require('net');

console.log("\n--- NODE TESTLERİ BAŞLADI ---");

// 1️⃣ OS KOMUTU – ENGELLENMELİ
try {
  child_process.exec("rm -rf /", () => {});
  console.log("❌ HATA: Tehlikeli komut engellenmedi");
} catch (e) {
  console.log("✅ OS komutu başarıyla engellendi");
}

// 2️⃣ DOSYA OKUMA – ENGELLENMELİ
fs.readFile("/etc/passwd", "utf8", (err) => {
  if (err) console.log("✅ Yetkisiz dosya okuma engellendi");
  else console.log("❌ HATA: Yetkisiz dosya okundu");
});

// 3️⃣ DOSYA OKUMA – İZİNLİ
fs.writeFileSync("izinli_test.txt", "OK");

fs.readFile("izinli_test.txt", "utf8", (err) => {
  if (!err) console.log("✅ İzinli dosya okuma başarılı");
  else console.log("❌ HATA: İzinli dosya engellendi");
});

// 4️⃣ NETWORK – ENGELLENMELİ
try {
  net.connect(80, "google.com");
  console.log("❌ HATA: Yetkisiz network erişimi");
} catch {
  console.log("✅ Network erişimi engellendi");
}

// 5️⃣ NETWORK – İZİNLİ
try {
  net.connect(80, "127.0.0.1");
  console.log("✅ İzinli network erişimi başarılı");
} catch {
  console.log("❌ HATA: İzinli network engellendi");
}
