export function routeFromHash(hash: string): string {
  try {
    const route=decodeURIComponent(hash.slice(1)) || 'Overview';
    return ['Overview','Agents','Threat Intelligence','File Scanner','Attack Lab','Security Events','Policies','Evaluations','Settings','Workspace'].includes(route) ? route : 'Overview';
  } catch { return 'Overview'; }
}
