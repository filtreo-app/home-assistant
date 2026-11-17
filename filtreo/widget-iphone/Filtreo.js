// Filtreo 2.0 — widget per l'iPhone (app Scriptable). Tre misure: piccolo, medio, grande.
// Dati, nell'ordine:
//   1. Casa (BASE, di solito via Tailscale);
//   2. il link da fuori casa (BASE_FUORI): passa i dati di Casa se c'è, altrimenti copre Cloudflare;
//   3. l'ultima copia salvata sul telefono, con scritto «Aggiornato alle HH:MM».
// Tutte le ore mostrate sono quelle del TELEFONO (anche la fine della pausa).
// Tocco sul widget: apre il pannello. Sullo scudo (medio e grande): pausa o ripresa, con conferma.
// Il file si scarica già pronto dal pannello (Dispositivi, «Il widget per l'iPhone»): per aggiornarlo
// basta riscaricarlo. Le scritte __…__ qui sotto le riempie il pannello (non toccarle).
const BASE = "__BASE__";             // Casa, es. http://<nodo>.ts.net:8447
const BASE_FUORI = "__BASE_FUORI__"; // link da fuori casa, es. https://<servizio>.workers.dev/p/<codice>
const K_FILE = "__CHIAVE__";         // chiave della barra (la stessa del Mac)
const PANNELLO = "__PANNELLO__";     // cosa si apre col tocco
const PORTACHIAVI = "filtreo-codice-widget";
const pronto = (x) => typeof x === "string" && x !== "" && !x.startsWith("__");

function chiave() {
  if (pronto(K_FILE)) return K_FILE;
  try { if (Keychain.contains(PORTACHIAVI)) return Keychain.get(PORTACHIAVI); } catch (e) { /* niente */ }
  return "";
}
let K = chiave();
let CHIAVE_ERRATA = false;

// ── colori del kit 2.0 (scuro) ──
const COL = {
  superficie: new Color("#171D25"), rialzo: new Color("#1F2732"), comando: new Color("#283241"),
  riga: new Color("#232B36"), bordo: new Color("#2C3644"),
  testo: new Color("#EEF2F6"), testo2: new Color("#A9B4C1"), testo3: new Color("#94A1B0"),
  verde: new Color("#36C678"), verdeTesto: new Color("#5FE39A"), menta: new Color("#A9EEC8"),
  tintaVerde: new Color("#173524"), disco: new Color("#14271F"),
  ambra: new Color("#F2B54A"), ambraFondo: new Color("#2E2410"),
  rosso: new Color("#FF8279"), rossoFondo: new Color("#381C1C"),
};

// ── file salvati sul telefono (copia dei dati e durata della pausa) ──
const F_COPIA = "filtreo-widget-ultimo.json";
const F_PREF = "filtreo-widget-pref.json";
function percorso(nome) {
  try { const fm = FileManager.local(); return fm.joinPath(fm.documentsDirectory(), nome); } catch (e) { return null; }
}
function leggiFile(nome) {
  try {
    const p = percorso(nome), fm = FileManager.local();
    if (p && fm.fileExists(p)) return JSON.parse(fm.readString(p));
  } catch (e) { /* niente */ }
  return null;
}
function scriviFile(nome, o) {
  try { const p = percorso(nome); if (p) FileManager.local().writeString(p, JSON.stringify(o)); } catch (e) { /* niente */ }
}

// ── lettura dei dati ──
async function unaVolta(url, attesa, conChiave) {
  const r = new Request(url);
  r.headers = conChiave ? { "X-Filtro": K } : {};
  r.timeoutInterval = attesa;
  const t = await r.loadString();
  if (r.response && r.response.statusCode === 403) { if (conChiave) CHIAVE_ERRATA = true; return null; }
  if (r.response && r.response.statusCode && r.response.statusCode !== 200) return null;
  const o = analizza(t);
  if (o) o.quando = Date.now();   // l'ora del TELEFONO in cui sono arrivati
  return o;
}

async function leggi() {
  const giri = [];
  if (pronto(BASE) && K) giri.push([BASE + "/barra", 5, true, "casa"]);
  if (pronto(BASE_FUORI)) giri.push([BASE_FUORI + "/barra", 12, false, "fuori"]);
  if (pronto(BASE) && K) giri.push([BASE + "/barra", 8, true, "casa"]);
  for (let i = 0; i < giri.length; i++) {
    const [url, attesa, conChiave, via] = giri[i];
    try {
      const o = await unaVolta(url, attesa, conChiave);
      if (o) {
        o.via = via;
        scriviFile(F_COPIA, o);
        return o;
      }
    } catch (e) { /* provo il prossimo */ }
    if (i < giri.length - 1) await new Promise((ok) => Timer.schedule(800, false, ok));
  }
  const c = leggiFile(F_COPIA);
  if (c && c.quando && Date.now() - c.quando < 3 * 24 * 3600 * 1000) { c.vecchio = true; return c; }
  return null;
}

function analizza(t) {
  try {
    const o = { disp: [], split: {} };
    for (const l of String(t || "").split("\n")) {
      const i = l.indexOf("=");
      if (i < 0) continue;
      const k = l.slice(0, i), v = l.slice(i + 1);
      if (k === "disp") { const p = v.split("|"); o.disp.push({ nome: p[0], bloccate: +p[1] || 0, richieste: +p[2] || 0 }); }
      else if (k === "disp_split") { const p = v.split("|"); o.split[p[0]] = { casa: +p[1] || 0, cloudflare: +p[2] || 0 }; }
      else if (k === "ult" || k === "top" || k === "modo") { /* non servono qui */ }
      else o[k] = v;
    }
    return o.raggiungibile === undefined ? null : o;
  } catch (e) { return null; }
}

// ── ora: sempre quella del telefono ──
const due = (n) => String(n).padStart(2, "0");
function oraDi(ms) { const d = new Date(+ms); return due(d.getHours()) + ":" + due(d.getMinutes()); }
function aggiornatoAlle(s) {
  const q = new Date(+s.quando), ora = new Date();
  const stessoGiorno = q.getFullYear() === ora.getFullYear() && q.getMonth() === ora.getMonth() && q.getDate() === ora.getDate();
  return "Ultimo aggiornamento: " + oraDi(s.quando) + (stessoGiorno ? "" : " del " + q.getDate() + "/" + (q.getMonth() + 1));
}
const it = (n) => String(Math.round(+n || 0)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");

// Il pannello scrive la fine della pausa come HH:MM nel fuso di CASA. Per averla sull'ora del telefono
// si usa la distanza (in minuti) tra la fine pausa e l'ora «agg» scritta nella stessa risposta:
// quella distanza vale in ogni fuso. Si accettano anche un orario completo (ISO) o un istante (secondi).
function fineDiPausa(s) {
  if (+s.pausa_fino_ts > 1e9) return +s.pausa_fino_ts * 1000;   // pannello 2.0: istante (secondi epoch), vale in ogni fuso
  if (+s.pausa_resta > 0) return (+s.quando || Date.now()) + (+s.pausa_resta) * 1000;   // pannello 1.9+: secondi che mancano
  const v = String(s.pausa_fino || "").trim();
  if (!v) return null;
  if (/^\d{9,13}$/.test(v)) { const n = +v; return n < 1e11 ? n * 1000 : n; }
  const m = /^(\d{1,2}):(\d{2})$/.exec(v);
  if (m) {
    const pm = +m[1] * 60 + +m[2];
    const q = +s.quando || Date.now();
    const a = /^(\d{1,2}):(\d{2})$/.exec(String(s.agg || "").trim());
    if (a) {
      const am = +a[1] * 60 + +a[2];
      return q - (q % 60000) + (((pm - am) % 1440 + 1440) % 1440) * 60000;
    }
    const d = new Date(q); d.setHours(+m[1], +m[2], 0, 0);
    return d.getTime() < q - 60000 ? d.getTime() + 86400000 : d.getTime();
  }
  const p = Date.parse(v);
  return isNaN(p) ? null : p;
}

// stato mostrato: tipo = ok | pausa | spento | nonrag ; casaGiu = Casa non risponde
function leggiStato(s) {
  if (!s) return { tipo: "nonrag", casaGiu: false, nome: "Non disponibile" };
  const casaGiu = s.raggiungibile !== "1";
  if (!casaGiu && s.acceso !== "1") {
    if (String(s.pausa_fino || "").trim()) {
      const fine = fineDiPausa(s);
      const resta = fine ? Math.max(0, fine - Date.now()) : 0;
      let frac = 1;
      if (fine) {
        const durate = [10, 60, 1440].map((x) => x * 60000).filter((x) => x >= resta);
        const tot = +s.pausa_totale > 0 ? +s.pausa_totale * 1000 : (durate.length ? durate[0] : Math.max(resta, 1));
        frac = Math.min(1, Math.max(0.04, resta / tot));
      }
      return { tipo: "pausa", casaGiu: false, nome: "In pausa", fine, frac };
    }
    return { tipo: "spento", casaGiu: false, nome: "Disattivato" };
  }
  return { tipo: "ok", casaGiu, nome: "Protetto" };
}

// ── disegni ──
function pt(x, y) { return new Point(x, y); }
function arco(dc, cx, cy, r, da, a, col, sp) {   // arco in senso orario, da «da» ad «a» (frazioni di giro, 0 = in alto)
  const p = new Path(), n = Math.max(4, Math.round(Math.abs(a - da) * 72));
  for (let i = 0; i <= n; i++) {
    const t = (da + (a - da) * i / n) * 2 * Math.PI;
    const q = pt(cx + r * Math.sin(t), cy - r * Math.cos(t));
    if (i) p.addLine(q); else p.move(q);
  }
  dc.addPath(p); dc.setStrokeColor(col); dc.setLineWidth(sp); dc.strokePath();
}
function anello(dc, c, r, sp, col) {
  const p = new Path(); p.addEllipse(new Rect(c - r, c - r, 2 * r, 2 * r));
  dc.addPath(p); dc.setStrokeColor(col); dc.setLineWidth(sp); dc.strokePath();
}

// lo scudo coi due anelli; dim = lato in punti (geometria del mockup: tela 44)
function scudo(dim, st) {
  const dc = new DrawContext();
  dc.size = new Size(dim, dim); dc.opaque = false; dc.respectScreenScale = true;
  const f = dim / 44, c = dim / 2;
  const neutro = st.tipo !== "ok";
  const spOut = 2 * f, spIn = 3 * f;
  anello(dc, c, 20.75 * f, spOut, neutro ? COL.comando : COL.menta);
  if (st.tipo === "ok" && st.casaGiu) {                    // Casa non risponde: anello interno tratteggiato
    for (let i = 0; i < 15; i++) arco(dc, c, c, 16.25 * f, i / 15, i / 15 + 0.44 / 15, COL.ambra, spIn);
  } else {
    anello(dc, c, 16.25 * f, spIn, neutro ? COL.comando : COL.verde);
  }
  if (st.tipo === "pausa") arco(dc, c, c, 20.75 * f, 0, st.frac, COL.ambra, 3 * f);
  const fondo = st.tipo === "ok" ? COL.disco : st.tipo === "pausa" ? COL.ambraFondo : COL.rialzo;
  const d = new Path(); d.addEllipse(new Rect(c - 12 * f, c - 12 * f, 24 * f, 24 * f));
  dc.addPath(d); dc.setFillColor(fondo); dc.fillPath();
  const T = (x, y) => pt((15 + x * 0.5833) * f, (15 + y * 0.5833) * f);   // griglia 24 del mockup
  const col = st.tipo === "ok" ? COL.verdeTesto : st.tipo === "pausa" ? COL.ambra : COL.testo3;
  dc.setStrokeColor(col); dc.setLineWidth(2.6 * 0.5833 * f);
  if (st.tipo === "pausa") {
    for (const x of [9.5, 14.5]) { const p = new Path(); p.move(T(x, 8)); p.addLine(T(x, 16)); dc.addPath(p); dc.strokePath(); }
    return dc.getImage();
  }
  const s = new Path();
  s.move(T(12, 3)); s.addLine(T(20, 6)); s.addLine(T(20, 12));
  s.addCurve(T(12, 21), T(20, 16.5), T(16.6, 20.2));
  s.addCurve(T(4, 12), T(7.4, 20.2), T(4, 16.5));
  s.addLine(T(4, 6)); s.closeSubpath();
  dc.addPath(s); dc.strokePath();
  if (st.tipo === "ok") {
    const k = new Path(); k.move(T(8.5, 12)); k.addLine(T(11, 14.5)); k.addLine(T(15.5, 9.5));
    dc.addPath(k); dc.strokePath();
  } else if (st.tipo === "spento") {
    const k = new Path(); k.move(T(5, 20)); k.addLine(T(19, 4)); dc.addPath(k); dc.strokePath();
  }
  return dc.getImage();
}

// Le ore del pannello sono nel fuso di Casa (Jetson). Si ruotano sull'ora del telefono: la distanza tra l'ora «agg» di Casa
// e la stessa ora sul telefono (istante agg_ts se c'è, altrimenti il momento in cui è arrivata la risposta) dà lo scarto in ore.
function oreDelTelefono(s, ore) {
  const a = /^(\d{1,2}):(\d{2})$/.exec(String(s.agg || "").trim());
  if (!a || ore.length < 24) return ore;
  const rif = +s.agg_ts > 1e9 ? +s.agg_ts * 1000 : (+s.quando || Date.now());
  const d = new Date(rif);
  let diff = (d.getHours() * 60 + d.getMinutes()) - (+a[1] * 60 + +a[2]);
  diff = ((diff % 1440) + 1440 + 720) % 1440 - 720;
  const sh = Math.round(diff / 60);
  if (!sh) return ore;
  const out = new Array(24).fill(0);
  ore.slice(0, 24).forEach((n, i) => { out[(((i + sh) % 24) + 24) % 24] = n; });
  return out;
}

// barre delle ore: da 0 a 23; l'ora di adesso è più chiara; le ore senza dati sono una riga sottile
function grafico(ore, w, h, gap) {
  const dc = new DrawContext();
  dc.size = new Size(w, h); dc.opaque = false; dc.respectScreenScale = true;
  const max = Math.max(1, ...ore), ora = new Date().getHours();
  const bw = (w - gap * 23) / 24;
  ore.slice(0, 24).forEach((n, i) => {
    const x = i * (bw + gap);
    const p = new Path();
    if (n <= 0) { p.addRoundedRect(new Rect(x, h - 2, bw, 2), 1, 1); dc.setFillColor(COL.comando); }
    else {
      const bh = Math.max(3, (h - 2) * n / max);
      p.addRoundedRect(new Rect(x, h - bh, bw, bh), 2, 2);
      dc.setFillColor(i === ora ? COL.verdeTesto : COL.verde);
    }
    dc.addPath(p); dc.fillPath();
  });
  return dc.getImage();
}

// ── pezzi del widget ──
const sb = (n) => Font.semiboldSystemFont(n), bd = (n) => Font.boldSystemFont(n), rg = (n) => Font.systemFont(n);

function testo(stack, t, font, colore) {
  const x = stack.addText(String(t));
  x.font = font; x.textColor = colore; x.lineLimit = 1;
  return x;
}
function immagine(stack, img, w, h) {
  const x = stack.addImage(img); x.imageSize = new Size(w, h); return x;
}
function quadratino(stack, colore) {
  const q = stack.addStack(); q.size = new Size(8, 8); q.cornerRadius = 2.5; q.backgroundColor = colore;
}
function pillola(stack, scritta, colore, fondo) {
  const p = stack.addStack(); p.setPadding(3, 9, 3, 9); p.cornerRadius = 8; p.backgroundColor = fondo;
  testo(p, scritta, sb(12.5), colore);
}
function colorePill(st) {
  return st.tipo === "ok" ? [COL.verdeTesto, COL.tintaVerde] : st.tipo === "nonrag" ? [COL.rosso, COL.rossoFondo]
    : st.tipo === "spento" ? [COL.rosso, COL.rossoFondo] : [COL.ambra, COL.ambraFondo];
}
// la riga che dice cosa succede, oltre allo stato (ambra); null se non serve
function nota(s, st) {
  if (st.tipo === "pausa") return st.fine ? "Riprende alle " + oraDi(st.fine) : "In pausa";
  if (st.tipo === "spento") return "Filtro di rete disattivato";
  if (st.casaGiu) return ["Casa non disponibile"];
  return null;
}
function totali(s) {
  const tot = +s.totale || +s.bloccate || 0;
  const haSplit = s.casa !== undefined && s.cloudflare !== undefined;
  return { tot, casa: +s.casa || 0, cf: +s.cloudflare || 0, haSplit, richieste: +s.richieste || 0, pc: +s.percento || 0 };
}
function legenda(stack, s, st, T, verticale) {
  const casaTxt = st.casaGiu ? "non disponibile" : it(T.casa);
  const casaCol = st.casaGiu ? COL.ambra : COL.testo;
  const voci = [[COL.verde, "Casa", casaTxt, casaCol], [COL.menta, "Filtreo Cloud", it(T.cf), COL.testo]];
  const box = verticale ? stack.addStack() : stack;
  if (verticale) box.layoutVertically();
  voci.forEach((v, i) => {
    const r = box.addStack(); r.centerAlignContent(); r.spacing = 6;
    if (verticale) r.size = new Size(0, 18);
    quadratino(r, v[0]);
    testo(r, v[1], rg(12.5), COL.testo2);
    if (verticale) r.addSpacer();
    testo(r, v[2], sb(12.5), v[3]);
    if (!verticale && i === 0) box.addSpacer(14);
  });
}
const ICONE = [["mac", "laptopcomputer"], ["macbook", "laptopcomputer"], ["iphone", "iphone"], ["telefono", "iphone"], ["mi ", "iphone"],
  ["tv", "tv"], ["ipad", "ipad"], ["tablet", "ipad"]];
function iconaDi(nome) {
  const n = String(nome).toLowerCase();
  for (const [k, v] of ICONE) if (n.startsWith(k) || n.includes(" " + k)) return v;
  return "desktopcomputer";
}

function widget(s) {
  const fam = config.widgetFamily || "medium";
  const st = leggiStato(s);
  const w = new ListWidget();
  w.backgroundColor = COL.superficie;
  w.setPadding(16, 16, 16, 16);
  if (pronto(PANNELLO)) w.url = PANNELLO;
  w.refreshAfterDate = new Date(Date.now() + (s && !s.vecchio ? 10 : 4) * 60 * 1000);

  // senza codice: niente da mostrare, si invita a incollarlo (come prima)
  if (!s && (CHIAVE_ERRATA || !K) && !pronto(BASE_FUORI)) {
    w.url = "scriptable:///run/" + encodeURIComponent(Script.name());
    immagine(w, scudo(36, st), 36, 36);
    w.addSpacer(8);
    testo(w, K ? "Codice del widget modificato" : "Codice del widget mancante", bd(15), COL.ambra).lineLimit = 2;
    testo(w, "Tocca e incolla il codice", rg(12.5), COL.testo2).lineLimit = 2;
    return w;
  }
  if (!s) {
    immagine(w, scudo(fam === "small" ? 44 : 36, st), fam === "small" ? 44 : 36, fam === "small" ? 44 : 36);
    w.addSpacer(8);
    testo(w, "Non disponibile", bd(fam === "small" ? 17 : 20), COL.testo).lineLimit = 2;
    testo(w, "Nuovo tentativo tra 5 min", rg(13), COL.testo2).lineLimit = 2;
    return w;
  }

  const T = totali(s);
  const n = nota(s, st);
  const vecchio = !!s.vecchio;
  const agg = aggiornatoAlle(s);
  const ver = s.versione ? "Filtreo " + s.versione : "";   // un numero solo, lo stesso del pannello
  const ore = oreDelTelefono(s, String(s.ore || "").split(",").map((x) => +x || 0));
  const haOre = ore.length >= 24;
  const urlScudo = pronto(BASE) && K ? "scriptable:///run/" + encodeURIComponent(Script.name()) + "?azione=" + (st.tipo === "pausa" || st.tipo === "spento" ? "riprendi" : "pausa") : null;

  if (fam === "small") {
    const im = immagine(w, scudo(44, st), 44, 44); im.leftAlignImage();
    w.addSpacer(8);
    testo(w, it(T.tot), bd(34), COL.testo);
    testo(w, "bloccate oggi", rg(13), COL.testo2);
    if (n) {
      const lines = Array.isArray(n) ? n : [n];
      lines.forEach((l) => testo(w, l, sb(12), COL.ambra));
    } else if (!vecchio) testo(w, T.pc + "% del traffico", rg(12), COL.testo3);
    if (vecchio) testo(w, agg, sb(11), COL.ambra).lineLimit = 2;
    w.addSpacer();
    return w;
  }

  if (fam === "medium") {
    const corpo = w.addStack(); corpo.topAlignContent();
    const sx = corpo.addStack(); sx.layoutVertically(); sx.size = new Size(120, 138);
    const riga = sx.addStack(); riga.centerAlignContent(); riga.spacing = 8;
    const im = immagine(riga, scudo(36, st), 36, 36);
    if (urlScudo) riga.url = urlScudo;
    testo(riga, st.nome, sb(15), COL.testo);
    sx.addSpacer();
    testo(sx, it(T.tot), bd(34), COL.testo);
    testo(sx, "bloccate oggi", rg(13), COL.testo2);
    if (st.tipo === "pausa") testo(sx, n, sb(12), COL.ambra);
    if (ver) testo(sx, ver, rg(10.5), COL.testo3);
    corpo.addSpacer(16);
    const dx = corpo.addStack(); dx.layoutVertically(); dx.size = new Size(150, 138);
    if (haOre) immagine(dx, grafico(ore, 150, 64, 2), 150, 64);
    dx.addSpacer(8);
    if (T.haSplit) legenda(dx, s, st, T, true);
    dx.addSpacer();
    const piede = dx.addStack(); piede.addSpacer();
    testo(piede, agg, rg(11.5), vecchio ? COL.ambra : COL.testo3);
    return w;
  }

  // grande
  const testa = w.addStack(); testa.centerAlignContent(); testa.spacing = 8;
  immagine(testa, scudo(36, st), 36, 36);
  if (urlScudo) testa.url = urlScudo;
  testo(testa, "Filtreo", bd(16), COL.testo);
  testa.addSpacer();
  const [pc, pf] = colorePill(st);
  pillola(testa, st.nome, pc, pf);
  w.addSpacer(12);
  const tre = w.addStack(); tre.centerAlignContent();
  const cella = (valore, etichetta, col, sep) => {
    const c = tre.addStack(); c.layoutVertically(); c.centerAlignContent();
    const a = testo(c, valore, bd(22), col); a.centerAlignText();
    const b = testo(c, etichetta, rg(12), COL.testo2); b.centerAlignText();
    return c;
  };
  cella(it(T.tot), "bloccate oggi", COL.verdeTesto);
  tre.addSpacer();
  cella(it(T.richieste), "richieste", COL.testo);
  tre.addSpacer();
  cella(T.pc + "%", "del traffico", COL.testo);
  w.addSpacer(12);
  const lg = w.addStack(); lg.centerAlignContent();
  if (T.haSplit) legenda(lg, s, st, T, false);
  lg.addSpacer();
  if (st.tipo === "pausa") testo(lg, n, sb(12), COL.ambra);
  w.addSpacer(8);
  if (haOre) {
    immagine(w, grafico(ore, 296, 72, 4), 296, 72);
    w.addSpacer(4);
    const ass = w.addStack();
    ["0", "6", "12", "18", "24"].forEach((x, i) => { if (i) ass.addSpacer(); testo(ass, x, rg(11.5), COL.testo3); });
  }
  w.addSpacer(10);
  const elenco = (s.disp || []).filter((d) => d.nome !== "Altri" || d.bloccate > 0).slice(0, 3);
  elenco.forEach((d, i) => {
    const r = w.addStack(); r.centerAlignContent(); r.spacing = 8; r.size = new Size(0, 34);
    const ic = r.addImage(SFSymbol.named(iconaDi(d.nome)).image);
    ic.imageSize = new Size(16, 16); ic.tintColor = COL.testo2;
    testo(r, d.nome, sb(13.5), COL.testo);
    r.addSpacer();
    testo(r, it(d.bloccate), rg(13.5), COL.testo2);
    if (i < elenco.length - 1) { const l = w.addStack(); l.size = new Size(0, 1); l.backgroundColor = COL.riga; }
  });
  w.addSpacer();
  const piede = w.addStack(); piede.centerAlignContent();
  if (st.casaGiu) testo(piede, n.join(" "), sb(12), COL.ambra);
  piede.addSpacer();
  testo(piede, agg, rg(11.5), vecchio ? COL.ambra : COL.testo3);
  if (ver) testo(w, ver, rg(10.5), COL.testo3);
  return w;
}

// ── azioni toccate dallo scudo: pausa / ripresa (con conferma) ──
async function chiama(percorsoUrl) {
  const r = new Request(BASE + percorsoUrl);
  r.method = "POST"; r.headers = { "X-Filtro": K }; r.timeoutInterval = 10;
  const t = await r.loadString();
  if (r.response && r.response.statusCode === 403) { CHIAVE_ERRATA = true; return null; }
  if (r.response && r.response.statusCode !== 200) return null;
  return String(t || "").trim();
}
async function avviso(titolo, msg, conAnnulla) {
  const a = new Alert(); a.title = titolo; a.message = msg;
  a.addAction(conAnnulla ? conAnnulla : "OK");
  if (conAnnulla) a.addCancelAction("Annulla");
  return a.present();
}
async function azione(nome) {
  if (!pronto(BASE) || !K) { await avviso("Richiede Casa", "La pausa richiede Casa. Si apre il pannello."); if (pronto(PANNELLO)) Safari.open(PANNELLO); return; }
  const pref = leggiFile(F_PREF) || {};
  // stesse scelte del pannello: 30 secondi (0.5), 10 minuti, 1 ora, fino a domani (1440), Senza scadenza (0 = spento)
  const min = [0.5, 10, 60, 1440, 0].includes(+pref.min) && pref.min !== "" && pref.min != null ? +pref.min : 10;
  const durata = min === 0.5 ? "30 secondi" : min === 10 ? "10 minuti" : min === 60 ? "1 ora" : min === 0 ? "senza scadenza" : "fino a domani";
  const ris = nome === "riprendi" ? null : durata;
  const conferma = nome === "riprendi" ? "Riprendi" : "Metti in pausa";
  const dom = nome === "riprendi" ? "La protezione riprende subito." : (min === 0 ? "La protezione resta disattivata fino alla ripresa." : "In pausa per " + durata);
  if ((await avviso(nome === "riprendi" ? "Riprendere la protezione?" : "Mettere in pausa?", dom, conferma)) !== 0) return;
  let esito = null;
  try { esito = await chiama(nome === "riprendi" ? "/barra/riprendi" : "/barra/pausa?" + (min === 0.5 ? "d=30s" : min === 0 ? "d=senza" : "min=" + min)); } catch (e) { esito = null; }
  await avviso(esito ? "Completato" : "Impossibile completare", esito || (CHIAVE_ERRATA ? "Codice non valido" : "Casa non disponibile. Riprova."));
}

async function chiediCodice(titolo) {
  const a = new Alert();
  a.title = titolo;
  a.message = "Copia la chiave della barra (la stessa dell'icona del Mac) e incollala qui.";
  a.addTextField("codice del widget", "");
  a.addAction("Salva");
  a.addCancelAction("Annulla");
  if ((await a.present()) !== 0) return false;
  const c = a.textFieldValue(0).replace(/\s+/g, "");
  if (!c) return false;
  Keychain.set(PORTACHIAVI, c);
  K = c; CHIAVE_ERRATA = false;
  return true;
}

const SENZA_INDIRIZZO = !pronto(BASE) && !pronto(BASE_FUORI);
const AZIONE = (args && args.queryParameters && args.queryParameters.azione) || "";

if (config.runsInWidget) {
  Script.setWidget(widget(SENZA_INDIRIZZO ? null : await leggi()));
} else if (SENZA_INDIRIZZO) {
  await avviso("Script non valido", "Modello del widget privo di indirizzi. Scarica la versione configurata dal pannello: Dispositivi › «Widget per iPhone».");
} else if (AZIONE === "pausa" || AZIONE === "riprendi") {
  await azione(AZIONE);
} else {
  // toccato a mano: se manca la chiave e Casa non risponde la chiedo; poi apro il pannello
  let s = await leggi();
  if (!s && (CHIAVE_ERRATA || !K)) {
    if (await chiediCodice(K ? "Codice del widget modificato" : "Codice del widget")) {
      s = await leggi();
      await avviso(s ? "Completato" : "Non configurato", s ? "Widget configurato. Torna alla schermata Home." : (CHIAVE_ERRATA ? "Codice non valido. Copialo di nuovo e riprova." : "Casa e indirizzo fuori casa non disponibili. Verifica la connessione."));
    }
  } else if (pronto(PANNELLO)) {
    Safari.open(PANNELLO);
  } else {
    await widget(s).presentMedium();
  }
}
Script.complete();
