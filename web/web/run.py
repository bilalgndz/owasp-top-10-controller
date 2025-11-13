#!/usr/bin/env python3
"""Web dashboard'u başlatmak için basit script"""

from web.app import app

if __name__ == "__main__":
    print("=" * 60)
    print("🔒 Gelişmiş Zafiyet Tarayıcı - Web Dashboard")
    print("=" * 60)
    print("\n🌐 Web arayüzü başlatılıyor...")
    print("📱 Tarayıcıda şu adresi açın: http://localhost:5000")
    print("\n⚠️  Durdurmak için Ctrl+C basın\n")
    print("=" * 60)
    
    app.run(debug=True, host="0.0.0.0", port=5000)

