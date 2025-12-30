// test_js.js
const fs = require('fs');

// Wrapper'ı devreye sok (ÇOK ÖNEMLİ)
require('./javascript_wrapper');

console.log("\n▶ JS Testleri Başlıyor...\n");

// ---------------------------------------------------------
// TEST 1: İzinli Dosya (js_allowed.txt)
// ---------------------------------------------------------
try {
    // Bu dosyanın gerçekten var olması lazım, yoksa 'file not found' alırız
    if (!fs.existsSync('js_allowed.txt')) {
        fs.writeFileSync('js_allowed.txt', 'Bu dosya okunabilir.');
    }

    const content = fs.readFileSync('js_allowed.txt', 'utf-8');
    console.log("✅ TEST 1 BAŞARILI: Dosya okundu ->", content);
} catch (e) {
    console.log("❌ TEST 1 HATA:", e.message);
}

console.log("\n--------------------------------\n");

// ---------------------------------------------------------
// TEST 2: Yasaklı Dosya (/etc/passwd veya herhangi bir dosya)
// ---------------------------------------------------------
try {
    // bridge.py içinde buna kural yazmadığımız için DENY dönmeli
    const secret = fs.readFileSync('secret_passwords.txt', 'utf-8');
    console.log("❌ TEST 2 HATA: Yasaklı dosya okundu (OLMAMALI)");
} catch (e) {
    console.log("✅ TEST 2 BAŞARILI: Erişim engellendi ->", e.message);
}

console.log("\n▶ Testler Bitti.");