/**
 * DAJANA RODRIGUEZ — Export fotiek z Google Sheets
 * ─────────────────────────────────────────────────
 * Ako použiť:
 *  1. V Google Sheets klikni  Extensions → Apps Script
 *  2. Vymaž všetok existujúci kód a vlož tento celý súbor
 *  3. Klikni na tlačidlo ▶ Run (funkcia exportPhotos)
 *  4. Keď ťa opýta na povolenia → povoliť
 *  5. Po dokončení dostaneš odkaz na stiahnutie JSON súboru
 */

function exportPhotos() {
  const sheet = SpreadsheetApp.getActiveSpreadsheet().getActiveSheet();
  const images = sheet.getImages();
  const result = [];

  images.forEach(function(img) {
    const anchorRow = img.getAnchorCell().getRow();
    const anchorCol = img.getAnchorCell().getColumn();

    // Fotka je v stĺpci C (3) — ak je inde, zmeň číslo
    if (anchorCol !== 3) return;

    // Kód produktu je v stĺpci A (1)
    const code = sheet.getRange(anchorRow, 1).getValue();
    if (!code) return;

    try {
      const blob     = img.getBlob();
      const base64   = Utilities.base64Encode(blob.getBytes());
      const mimeType = blob.getContentType() || 'image/jpeg';

      result.push({
        code:  String(code).trim(),
        photo: 'data:' + mimeType + ';base64,' + base64
      });

      Logger.log('✓ ' + code);
    } catch (e) {
      Logger.log('✗ Chyba pri ' + code + ': ' + e.message);
    }
  });

  if (result.length === 0) {
    SpreadsheetApp.getUi().alert(
      'Nenašli sa žiadne fotky.\n\n' +
      'Skontroluj, že fotky sú v stĺpci C (tretí stĺpec).\n' +
      'Ak sú v inom stĺpci, zmeň číslo "3" na riadku "if (anchorCol !== 3)".'
    );
    return;
  }

  // Ulož ako JSON súbor na Google Drive
  const json = JSON.stringify(result);
  const file = DriveApp.createFile(
    'limitky-photos-export.json',
    json,
    MimeType.PLAIN_TEXT
  );
  file.setSharing(DriveApp.Access.ANYONE_WITH_LINK, DriveApp.Permission.VIEW);

  SpreadsheetApp.getUi().alert(
    '✅ Hotovo! Exportovaných ' + result.length + ' fotiek.\n\n' +
    'Stiahni JSON súbor tu:\n' + file.getDownloadUrl() + '\n\n' +
    'Potom ho nahraj na stránke:\nhttps://limitky-api.olha.workers.dev/import-photos.html'
  );
}
