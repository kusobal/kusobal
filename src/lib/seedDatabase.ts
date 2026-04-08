import dbConnect from './mongodb';
import Update from '@/models/Update';

const sampleUpdates = [
  // ESXi Updates
  {
    productType: 'ESXi',
    vendor: 'Broadcom',
    version: '8.0.3',
    patch: '8.0.3P',
    releaseDate: new Date('2024-03-15'),
    category: 'Security',
    severity: 'High',
    releaseNotesEN: `ESXi 8.0.3P includes critical security patches:
- CVE-2024-XXXX: Fixed privilege escalation vulnerability
- CVE-2024-XXXX: Fixed memory corruption issue
- Performance improvements in VM scheduling
- Improved networking stack stability
Recommended for all customer deployments.`,
    releaseNotesTR: `ESXi 8.0.3P kritik güvenlik yamalarını içerir:
- CVE-2024-XXXX: Ayrıkalık yükselmesi güvenlik açığı giderildi
- CVE-2024-XXXX: Bellek bozulması sorunu düzeltildi
- VM zamanlama performans iyileştirmeleri
- Ağ yığını stabilite iyileştirmeleri
Tüm müşteri dağıtımları için önerilir.`,
    url: 'https://support.broadcom.com/web/ecx/support-content-notification',
  },
  {
    productType: 'ESXi',
    vendor: 'Broadcom',
    version: '8.0.2',
    patch: '8.0.2P',
    releaseDate: new Date('2024-02-20'),
    category: 'Bug Fix',
    severity: 'Medium',
    releaseNotesEN: `ESXi 8.0.2P Update:
- Fixed vMotion failures in edge cases
- Improved storage adapter stability
- Fixed NVMe driver issues
- Updated firmware compatibility`,
    releaseNotesTR: `ESXi 8.0.2P Güncellemesi:
- vMotion hataları kenar durumlarda düzeltildi
- Depolama adaptörü stabilitesi iyileştirildi
- NVMe sürücü sorunları düzeltildi
- Firmware uyumluluğu güncellendi`,
    url: 'https://support.broadcom.com/web/ecx/support-content-notification',
  },
  // vCenter Updates
  {
    productType: 'vCenter',
    vendor: 'VMware',
    version: '8.0.1',
    patch: '8.0.1a',
    releaseDate: new Date('2024-03-10'),
    category: 'Bug Fix',
    severity: 'Medium',
    releaseNotesEN: `vCenter Server 8.0.1a Update:
- Fixed vSphere Client connectivity issues
- Improved database performance for large environments
- Fixed backup/restore functionality
- Updated SSL certificates
Please update within 30 days.`,
    releaseNotesTR: `vCenter Server 8.0.1a Güncellemesi:
- vSphere Client bağlantı sorunları düzeltildi
- Büyük ortamlar için veritabanı performansı iyileştirildi
- Yedekleme/geri yükleme işlevi düzeltildi
- SSL sertifikaları güncellendi
Lütfen 30 gün içinde güncelleyin.`,
    url: 'https://docs.vmware.com/en/vCenter-Server/8.0/',
  },
  {
    productType: 'vCenter',
    vendor: 'VMware',
    version: '8.0',
    patch: '8.0.0',
    releaseDate: new Date('2024-01-15'),
    category: 'Feature',
    severity: 'Low',
    releaseNotesEN: `vCenter Server 8.0 Release:
- New user interface
- Improved scalability
- Enhanced security features
- Better API compatibility`,
    releaseNotesTR: `vCenter Server 8.0 Sürümü:
- Yeni kullanıcı arayüzü
- İyileştirilmiş ölçeklenebilirlik
- Geliştirilmiş güvenlik özellikleri
- Daha iyi API uyumluluğu`,
    url: 'https://docs.vmware.com/en/vCenter-Server/8.0/',
  },
  // iDRAC Updates
  {
    productType: 'iDRAC',
    vendor: 'Dell',
    version: '10.1.0',
    patch: '10.1.0.1',
    releaseDate: new Date('2024-03-05'),
    category: 'Security',
    severity: 'Critical',
    releaseNotesEN: `iDRAC10 Firmware 10.1.0.1:
- CRITICAL: Fixed IPMI vulnerability
- Fixed Redfish API authentication bypass
- Improved thermal management
- Enhanced logging capabilities
RECOMMENDED: Apply immediately`,
    releaseNotesTR: `iDRAC10 Firmware 10.1.0.1:
- KRİTİK: IPMI güvenlik açığı düzeltildi
- Redfish API kimlik doğrulama bypass'ı düzeltildi
- Termal yönetimi iyileştirildi
- Günlükleme yetenekleri iyileştirildi
ÖNERILEN: Hemen uygulayin`,
    url: 'https://www.dell.com/support/home/',
  },
  {
    productType: 'iDRAC',
    vendor: 'Dell',
    version: '9.4.50',
    patch: '9.4.50.00',
    releaseDate: new Date('2024-02-28'),
    category: 'Bug Fix',
    severity: 'High',
    releaseNotesEN: `iDRAC9 Firmware 9.4.50:
- Fixed Power Management issues
- Improved fan control logic
- Fixed sensor reading errors
- Stability improvements`,
    releaseNotesTR: `iDRAC9 Firmware 9.4.50:
- Güç Yönetimi sorunları düzeltildi
- Fan kontrol mantığı iyileştirildi
- Sensör okuma hataları düzeltildi
- Stabilite iyileştirmeleri`,
    url: 'https://www.dell.com/support/home/',
  },
  // Veeam Updates
  {
    productType: 'Veeam',
    vendor: 'Veeam',
    version: '12.1',
    patch: '12.1.1742',
    releaseDate: new Date('2024-03-12'),
    category: 'Security',
    severity: 'High',
    releaseNotesEN: `Veeam Backup 12.1.1742:
- Security patch for encryption vulnerabilities
- Improved backup performance
- Fixed restore issues
- Enhanced reporting
Critical for production environments.`,
    releaseNotesTR: `Veeam Backup 12.1.1742:
- Şifreleme açıkları için güvenlik yaması
- Yedekleme performansı iyileştirildi
- Geri yükleme sorunları düzeltildi
- Rapor iyileştirmeleri
Üretim ortamları için kritiktir.`,
    url: 'https://www.veeam.com/support.html',
  },
  {
    productType: 'Veeam',
    vendor: 'Veeam',
    version: '12.1',
    patch: '12.1.1700',
    releaseDate: new Date('2024-02-15'),
    category: 'Bug Fix',
    severity: 'Medium',
    releaseNotesEN: `Veeam Backup 12.1.1700:
- Fixed license activation issues
- Improved proxy performance
- Fixed backup copy jobs
- UI improvements`,
    releaseNotesTR: `Veeam Backup 12.1.1700:
- Lisans aktivasyon sorunları düzeltildi
- Proxy performansı iyileştirildi
- Yedek kopyalama işleri düzeltildi
- UI iyileştirmeleri`,
    url: 'https://www.veeam.com/support.html',
  },
  // iLO Updates
  {
    productType: 'iLO',
    vendor: 'HP',
    version: '6.50',
    patch: '6.50.10.0',
    releaseDate: new Date('2024-03-01'),
    category: 'Security',
    severity: 'High',
    releaseNotesEN: `iLO 6 Firmware 6.50.10.0:
- Security update for web vulnerabilities
- Improved certificate handling
- Fixed remote console issues
- Enhanced session management`,
    releaseNotesTR: `iLO 6 Firmware 6.50.10.0:
- Web güvenlik açıkları için güvenlik güncellemesi
- Sertifika yönetimi iyileştirildi
- Uzak konsol sorunları düzeltildi
- Oturum yönetimi iyileştirildi`,
    url: 'https://support.hpe.com/',
  },
  {
    productType: 'iLO',
    vendor: 'HP',
    version: '6.40',
    patch: '6.40.15.0',
    releaseDate: new Date('2024-01-20'),
    category: 'Bug Fix',
    severity: 'Medium',
    releaseNotesEN: `iLO 6 Firmware 6.40.15.0:
- Fixed virtual media mounting
- Improved SNMP stability
- Fixed DHCP issues
- Performance optimizations`,
    releaseNotesTR: `iLO 6 Firmware 6.40.15.0:
- Sanal ortam bağlama sorunları düzeltildi
- SNMP stabilitesi iyileştirildi
- DHCP sorunları düzeltildi
- Performans optimizasyonları`,
    url: 'https://support.hpe.com/',
  },
  // BIOS Updates
  {
    productType: 'BIOS',
    vendor: 'Dell',
    version: '2.24.2',
    patch: '2.24.2',
    releaseDate: new Date('2024-02-25'),
    category: 'Security',
    severity: 'High',
    releaseNotesEN: `PowerEdge BIOS 2.24.2:
- Microcode update for CPU vulnerabilities
- Improved memory stability
- Fixed boot issues
- Enhanced security settings`,
    releaseNotesTR: `PowerEdge BIOS 2.24.2:
- CPU açıkları için mikro kod güncellemesi
- Bellek stabilitesi iyileştirildi
- Boot sorunları düzeltildi
- Geliştirilmiş güvenlik ayarları`,
    url: 'https://www.dell.com/support/home/',
  },
];

export async function seedDatabase() {
  try {
    await dbConnect();
    
    const count = await Update.countDocuments();
    
    // Eğer veri yoksa, sample veriyi ekle
    if (count === 0) {
      console.log('📊 Seeding database with sample updates...');
      await Update.insertMany(sampleUpdates);
      console.log(`✅ Successfully seeded ${sampleUpdates.length} updates`);
    } else {
      console.log(`✅ Database already has ${count} updates`);
    }
  } catch (error) {
    console.error('❌ Error seeding database:', error);
  }
}
