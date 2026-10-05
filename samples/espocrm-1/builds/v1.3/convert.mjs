// Sample seller build, v1.3. Same as v1.4, but the duplicate check was never written.
const TYPES = ["Account", "Contact", "Opportunity"];

export function convert(store, userId, leadId, values = {}) {
  const user = store.users.find((u) => u.id === userId);
  const lead = store.leads.find((l) => l.id === leadId);
  if (!user || !lead) return { ok: false, error: "not_found" };
  if (!can(user, "Lead", "edit")) return { ok: false, error: "forbidden" };
  for (const type of TYPES) {
    if (values[type] && !can(user, type, "create")) return { ok: false, error: "forbidden" };
  }
  const created = {};
  for (const type of TYPES) {
    if (!values[type]) continue;
    const record = { id: `${type[0]}-${store[type].length + 1}`, ...values[type] };
    store[type].push(record);
    created[type] = record.id;
  }
  lead.status = "Converted";
  return { ok: true, created };
}

function can(user, scope, action) {
  return (user.acl[scope] || []).includes(action);
}
