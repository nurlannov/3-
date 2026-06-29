import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-app.js';
import { getAuth } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-auth.js';
import { getFirestore } from 'https://www.gstatic.com/firebasejs/10.14.1/firebase-firestore.js';

export const firebaseConfig = {
  apiKey: 'AIzaSyChj4N2YdVSWVOdZdjgXzKQ639vvMf-T7k',
  authDomain: 'hotel-46173.firebaseapp.com',
  projectId: 'hotel-46173',
  storageBucket: 'hotel-46173.firebasestorage.app',
  messagingSenderId: '484899892589',
  appId: '1:484899892589:web:d54b67a62c97d13b293e64'
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

export const toInt = value => Math.max(0, Number.parseInt(value, 10) || 0);
export const formatDateLocal = date => {
  const y = date.getFullYear();
  const m = String(date.getMonth() + 1).padStart(2, '0');
  const d = String(date.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
};
export const parseLocalDate = value => {
  if (!value) return null;
  const [y, m, d] = String(value).split('-').map(Number);
  return y && m && d ? new Date(y, m - 1, d) : null;
};
export const todayString = () => formatDateLocal(new Date());
export const sanitizeText = value => String(value ?? '')
  .replace(/<[^>]*>/g, '')
  .replace(/javascript:/gi, '')
  .trim();
export const escapeHtml = value => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  .replace(/"/g, '&quot;').replace(/'/g, '&#x27;');

export const normalizeOutTime = value => ['B', 'L', 'D'].includes(value) ? value : 'B';
export const outTimeLabel = value => ({ B:'После завтрака', L:'После обеда', D:'После ужина' })[normalizeOutTime(value)];
export const mealPlanLabel = value => ({ B:'Только завтрак', BL:'Завтрак + обед', FULL:'Полное питание' })[value] || 'Индивидуально';

export function normalizeCalendarDay(day = {}, adults = 0, kids = 0) {
  const a = toInt(adults), k = toInt(kids);
  const B = !!day.B, L = !!day.L, D = !!day.D;
  const hasCounts = ['BA','BK','LA','LK','DA','DK'].some(key => key in day);
  return {
    date: String(day.date || ''), B, L, D,
    BA: B ? toInt(hasCounts ? day.BA : a) : 0,
    BK: B ? toInt(hasCounts ? day.BK : k) : 0,
    LA: L ? toInt(hasCounts ? day.LA : a) : 0,
    LK: L ? toInt(hasCounts ? day.LK : k) : 0,
    DA: D ? toInt(hasCounts ? day.DA : a) : 0,
    DK: D ? toInt(hasCounts ? day.DK : k) : 0
  };
}

export function validateRoom(value) {
  const room = sanitizeText(value);
  if (!/^[^<>{}\[\]]{1,20}$/.test(room)) throw new Error('Проверьте номер комнаты. Допустимы цифры, буквы, пробел, / и дефис.');
  return room;
}

export function validateGuest(data) {
  const room = validateRoom(data.room);
  const name = sanitizeText(data.name);
  if (!/^[\p{L}\s-]{2,50}$/u.test(name)) throw new Error('Имя должно содержать от 2 до 50 букв.');
  const adults = toInt(data.adults), kids = toInt(data.kids);
  if (adults > 99 || kids > 99) throw new Error('Проверьте количество взрослых и детей.');
  if (!data.out) throw new Error('Укажите дату выезда.');
  return { ...data, room, name, adults, kids, notes:sanitizeText(data.notes), guestNotes:sanitizeText(data.guestNotes), outTime:normalizeOutTime(data.outTime) };
}
