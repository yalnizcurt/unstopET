type Row=Record<string,any>;
export function childInventory(rows:Row[],prefix=''):Row[] {return rows.flatMap(r=>[{...r,path:prefix+r.filename},...childInventory(r.children||[],prefix+r.filename+' / ')]);}
