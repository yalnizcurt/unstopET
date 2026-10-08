export function routeFromHash(hash: string): string {
  try { return decodeURIComponent(hash.slice(1)) || 'Overview'; }
  catch { return 'Overview'; }
}
