// C1 · A person without permission cannot turn a lead into a customer.
import { check, expect, finish, load, said } from "./check.mjs";

const { convert, fresh } = await load();

await check("a read-only user cannot convert a lead", () => {
  const store = fresh();
  const out = convert(store, "u-viewer", "L-102", { Contact: { name: "Jonas Lie" } });
  expect(out.error === "forbidden", said(out));
  expect(store.leads[1].status === "New", "the lead changed anyway");
});

await check("a user without account rights cannot create an account", () => {
  const store = fresh();
  const out = convert(store, "u-no-account", "L-102", { Account: { name: "Fjordtech AS" } });
  expect(out.error === "forbidden", said(out));
  expect(store.Account.length === 1, "an account was created anyway");
});

await check("control: a sales rep with rights can convert", () => {
  const store = fresh();
  const out = convert(store, "u-sales", "L-102", { Account: { name: "Fjordtech AS" }, Contact: { name: "Jonas Lie" } });
  expect(out.ok, said(out));
});

finish();
