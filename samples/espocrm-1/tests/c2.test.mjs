// C2 · When the same customer already exists, conversion stops.
import { check, expect, finish, load, said } from "./check.mjs";

const { convert, fresh } = await load();
const existing = { Account: { name: "Nordlys AS" }, Contact: { name: "Ingrid Berg" } };

await check("a lead whose account already exists stops with a conflict", () => {
  const out = convert(fresh(), "u-sales", "L-101", existing);
  expect(out.error === "conflict", said(out));
});

await check("no second “Nordlys AS” account is created", () => {
  const store = fresh();
  convert(store, "u-sales", "L-101", existing);
  const count = store.Account.filter((a) => a.name === "Nordlys AS").length;
  expect(count === 1, `there are now ${count}`);
});

await check("the lead is left unconverted", () => {
  const store = fresh();
  convert(store, "u-sales", "L-101", existing);
  expect(store.leads[0].status === "New", `its status is ${store.leads[0].status}`);
});

await check("control: a new company still converts", () => {
  const out = convert(fresh(), "u-sales", "L-102", { Account: { name: "Fjordtech AS" } });
  expect(out.ok, said(out));
});

finish();
