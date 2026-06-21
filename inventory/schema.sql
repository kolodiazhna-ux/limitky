-- Dajana Rodriguez — Sklad / Inventár
-- Cloudflare D1 schema. Last-write-wins (updated_at sa nastavuje pri každej zmene).

CREATE TABLE IF NOT EXISTS products (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  code        TEXT NOT NULL,
  name        TEXT NOT NULL,
  photo       TEXT DEFAULT '',          -- base64 data URL (skomprimovaná fotka)
  qty         INTEGER DEFAULT 0,
  place       TEXT DEFAULT '',
  date        TEXT DEFAULT '',          -- ISO YYYY-MM-DD
  descr        TEXT DEFAULT '',
  price        REAL DEFAULT 0,
  note         TEXT DEFAULT '',
  status       TEXT DEFAULT '',         -- Výroba / Bratislava / Na ceste… / Partizánske
  transfer_no  TEXT DEFAULT '',         -- číslo presunu
  photo_status TEXT DEFAULT '',         -- Poslané na fotenie / Vyfotené
  photo_link   TEXT DEFAULT '',         -- odkaz na fotky
  web_sk       TEXT DEFAULT '',         -- odkaz na produkt Web SK
  web_cz       TEXT DEFAULT '',         -- odkaz na produkt Web CZ
  kovanie      TEXT DEFAULT '',         -- Zlaté / Strieborné
  row_color    TEXT DEFAULT '',         -- ručná farba riadku
  bucket       TEXT DEFAULT '',         -- '' aktívne / 'mail' / 'soldout'
  updated_at   INTEGER DEFAULT 0,       -- epoch ms poslednej úpravy
  updated_by   TEXT DEFAULT ''          -- meno/iniciálka kto upravil
);

CREATE INDEX IF NOT EXISTS idx_products_code ON products(code);

-- Počiatočné dáta (seed) — spustí sa len ak je tabuľka prázdna pri prvom nasadení.
INSERT INTO products (code, name, qty, place, date, descr, price, note, updated_at) VALUES
('MIALIM67-Z',     'Mia Limitka 67 Zlatá',                      6,  'RRR', '2026-01-14', 'čierna so zlatým kovaním', 275, '', 0),
('MIALIM68',       'Mia Limitka 68 Strieborná',                 7,  'RRR', '2026-01-21', 'nude s výšivkou japonska čerešňa', 285, '', 0),
('KTLIM41',        'Kozmetická taštička Limitka 41 Strieborná', 4,  'RRR', '2026-01-21', 'nude s výšivkou japonska čerešňa', 65,  '', 0),
('MIALIM69-Z',     'Mia Limitka 69 Zlatá',                      10, 'RRR', '2026-01-28', 'zlatá s výšivkou japonska čerešňa', 285, '', 0),
('LILLIM57-Z',     'Lily Limitka 57 Zlatá',                     3,  'RRR', '2026-02-04', 'ružová s výšivkou', 305, '', 0),
('MIALIM70',       'Mia Limitka 70 Strieborná',                 3,  'RRR', '2026-02-11', 'modrá', 275, 'línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe', 0),
('MIALIM71',       'Mia Limitka 71 Strieborná',                 3,  'RRR', '2026-02-18', 'ružovo/fialová', 275, 'línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe', 0),
('LILLIM58',       'Lily Limitka 58 Strieborná',                4,  'RRR', '2026-02-25', 'modrá', 290, 'línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe', 0),
('LILLIM59',       'Lily Limitka 59 Strieborná',                2,  'RRR', '2026-03-04', 'ružovo/fialová', 290, 'línie na koži môžu byť vertikálne alebo horizontálne – info doplniť do popisu v produkte na webe', 0),
('MICLIM10-Z',     'Michaela Limitka 10 Zlatá',                 6,  'RRR', '2026-03-11', 'čierna', 300, '', 0),
('KTLIM42-Z',      'Kozmetická taštička Limitka 42 Zlatá',      2,  'RRR', '2026-03-18', 'bledohnedá', 65,  '', 0),
('KTLIM43-Z',      'Kozmetická taštička Limitka 43 Zlatá',      3,  'RRR', '2026-03-18', 'tmavohnedá', 65,  '', 0),
('LILLIM60-Z',     'Lily Limitka 60 Zlatá',                     3,  'RRR', '2026-03-18', 'bledohnedá', 305, '', 0),
('MIALIM72-Z',     'Mia Limitka 72 Zlatá',                      3,  'RRR', '2026-03-25', 'farebný odlesk', 320, '', 0),
('MIALIM73',       'Mia Limitka 73 Strieborná',                 4,  'RRR', '2026-04-01', 'marhuľová s výšivkou', 320, 'dá sa personalizovať - nafotiť aj zozadu a nahodiť na web', 0),
('MIALIM74',       'Mia Limitka 74 Strieborná',                 2,  'RRR', '2026-04-08', 'ružová s výšivkou', 320, 'dá sa personalizovať - nafotiť aj zozadu a nahodiť na web', 0),
('MARLIM15',       'Martina Limitka 15 Strieborná',             5,  'RRR', '2026-04-15', 'modrá s výšivkou', 305, '', 0),
('',               'khloe limitky z DR',                        0,  '',    '2026-04-22', '', 0, '', 0),
('MARLIM16',       'Martina Limitka 16 Strieborná',             4,  'RRR', '2026-04-29', 'bledohnedá s výšivkou', 305, '', 0),
('LILLIM62',       'Lily Limitka 62 Strieborná',                4,  'RRR', '2026-05-06', 'tmavomodrá s výšivkou', 305, '', 0),
('MIALIM75',       'Mia Limitka 75 Zlatá',                      5,  'RRR', '2026-05-13', 'modrá', 275, '', 0),
('MIALIM76',       'Mia Limitka 76 Zlatá',                      2,  'RRR', '2026-05-20', 'žltá', 275, '', 0),
('MARLIM17',       'Martina Limitka 17 Strieborná',             5,  'RRR', '2026-05-27', 'hnedá', 305, '', 0),
('MIALIM77-002',   'Mia Limitka 77 STRIEBORNA',                 1,  'RRR', '2026-06-03', 'modrá', 275, '- CHYNBA', 0),
('MIALIM78',       'Mia Limitka 78 Strieborná',                 2,  'RRR', '2026-06-10', 'modrá', 275, '', 0),
('MARLIM18',       'Martina Limitka 18 Strieborná',             3,  'RRR', '2026-06-17', 'tyrkysová', 305, '', 0),
('LILLIM61',       'Lily Limitka 61 Strieborná',                3,  'RRR', '2026-06-24', 'bledomodrý s výšivkou', 305, '', 0),
('LILLIM63',       'Lily Limitka 63 Strieborná',                6,  'RRR', '2026-07-01', 'tyrkysová s výšivkou', 305, '', 0),
('LILLIM64-Z',     'Lily Limitka 64 Zlatá',                     3,  'RRR', '2026-07-08', 'Bordová s výšivkou', 305, '', 0),
('LILLIM55-Z-001', 'Lily Limitka 55 zlatá',                     1,  'RRR', '2026-07-15', 'Ružová s výšivkou', 305, '', 0),
('MIALIM65-Z-001', 'Mia Limitka 65 zlatá',                      1,  'RRR', '2026-07-22', 'Tmavozelená s výšivkou', 320, '', 0),
('MIALIM-Z-043',   'Mia Limitka zlatá',                         1,  'RRR', '2026-07-29', 'Bledomodrá s výšivkou', 320, '', 0),
('LILLIM65',       'Lily Limitka 65 Strieborná',                4,  'RRR', '2026-08-05', 'kráľovská modrá s výšivkou', 305, '', 0),
('KTLIM44-Z',      'Kozmetická taštička Limitka 44 Zlatá',      2,  'RRR', '2026-08-12', 'farebný odlesk-fialová', 60, '', 0),
('KTLIM45-Z',      'Kozmetická taštička Limitka 45 Zlatá',      1,  'RRR', '2026-08-12', 'Farebný odlesk', 60, '', 0),
('LEALIM1-Z',      'Leanka Limitka 1 Zlatá',                    5,  'RRR', '2026-08-05', 'Červená s potlačou', 305, '', 0),
('KTLIM46-Z',      'Kozmetická taštička Limitka 46 Zlatá',      2,  'RRR', '2026-08-05', 'Červená s potlačou', 60, '', 0),
('MARLIM19',       'Martina Limitka 19 Strieborná',             6,  'RRR', '2026-08-12', 'Modrá s výšivkou', 305, '', 0),
('ADRLIM8',        'Adriana Limitka 8 Strieborná',              5,  'RRR', '2026-08-19', 'Cyklamenova s výšivkou', 325, '', 0);
