// javascript_wrapper.js
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

// 1. Orijinal fonksiyonu sakla
const originalReadFileSync = fs.readFileSync;

// 2. Python ile konuşan kontrol fonksiyonu
function checkPermission(resourceType, resource, action) {
    const requestData = JSON.stringify({
        resource_type: resourceType,
        resource: resource,
        action: action
    });

    try {
        // bridge.py dosyasını çalıştır
        // "python" komutu çalışmazsa "python3" olarak değiştirilebilir sisteme göre
        const command = `python bridge.py '${requestData}'`;
        
        // Komutu senkron (bekleyerek) çalıştır
        const output = execSync(command, { encoding: 'utf-8' });
        const result = JSON.parse(output);

        // Eğer izin yoksa HATA FIRLAT
        if (result.decision === 'deny') {
            throw new Error(`[ScriptSecure] ERİŞİM ENGELLENDİ: ${result.reason}`);
        }
        
        return true; // İzin var, devam et

    } catch (e) {
        // Python hatası veya engelleme hatası
        if (e.message.includes('[ScriptSecure]')) throw e;
        throw new Error(`[Authorization System Error] ${e.message}`);
    }
}

// 3. Wrapper'ı Tanımla (fs.readFileSync'i değiştiriyoruz)
fs.readFileSync = function(filePath, options) {
    const fileName = path.basename(filePath); // Sadece dosya adını alıyoruz (Basitlik için)
    
    console.log(`Checking permission for: ${fileName}...`);
    
    // Python'a sor
    checkPermission("file", fileName, "read");

    // İzin varsa orijinal fonksiyonu çağır
    return originalReadFileSync(filePath, options);
};

console.log("✅ JavaScript Wrapper Yüklendi ve Aktif!");