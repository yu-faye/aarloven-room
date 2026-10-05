// C3 · After conversion, the lead is marked converted.
import { check, expect, finish, load, said } from "./check.mjs";

const { convert, fresh } = await load();

await check("a finished conversion sets the lead to Converted", () => {
  const store = fresh();
  const out = convert(store, "u-sales", "L-102", { Contact: { name: "Jonas Lie" } });
  expect(out.ok, said(out));
  expect(store.leads[1].status === "Converted", `its status is ${store.leads[1].status}`);
});

await check("control: a refused conversion leaves the status alone", () => {
  const store = fresh();
  convert(store, "u-viewer", "L-102", { Contact: { name: "Jonas Lie" } });
  expect(store.leads[1].status === "New", `its status is ${store.leads[1].status}`);
});

finish();
