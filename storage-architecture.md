# ShinyDB Storage Architecture

## System Store (store_id=0) - Metadata Storage

This contains all metadata about spaces, stores, and indexes:

| Key (u128)      | doc_type | Value (BSON)                                                     | Namespace           |
| --------------- | -------- | ---------------------------------------------------------------- | ------------------- |
| keygen(0, 0, 1) | 2        | `{name: "system", ns: "system", id: 0, store_id=0`               | system              |
| keygen(0, 0, 1) | 2        | `{name: "spaces", ns: "system.spaces", id: 1, store_id=0}`       | system.spaces       |
| keygen(0, 0, 1) | 2        | `{name: "stores", ns: "system.stores", id: 2, store_id=0}`       | system.stores       |
| keygen(0, 0, 2) | 2        | `{name: "indexes", ns: "system.indexes", id: 3, store_id=0}`     | system.indexes      |
| keygen(0, 0, 2) | 2        | `{name: "users", ns: "system.users", id: 4, store_id=0}`         | system.users        |
| keygen(0, 0, 2) | 2        | `{name: "backups", ns: "system.backups", id: 5, store_id=0}`     | system.backups      |
| keygen(1, 0, 1) | 1        | `{name: "sales", ns: "system.spaces.sales", id: 6, store_id=1}`  | system.spaces.sales |
| keygen(2, 0, 2) | 2        | `{name: "orders", ns: "system.stores.sales", id: 7, store_id=2}` | system.stores.sale  |

---

## User Store (store_id=101) - Data Storage

This is the actual "orders" store containing business data:

| Key (u128)        | doc_type | Value (JSON)                                                               | Namespace    |
| ----------------- | -------- | -------------------------------------------------------------------------- | ------------ |
| keygen(101, 0, 4) | 4        | `{order_id: "ORD001", customer: "Alice", date: "2026-01-01", amount: 500}` | sales.orders |
| keygen(101, 0, 4) | 4        | `{order_id: "ORD002", customer: "Bob", date: "2026-01-02", amount: 750}`   | sales.orders |
| keygen(101, 0, 4) | 4        | `{order_id: "ORD003", customer: "Alice", date: "2026-01-03", amount: 320}` | sales.orders |

---

## User Store (store_id=102) - Data Storage

"items" store containing order line items:

| Key (u128)        | doc_type | Value (JSON)                                                                        | Namespace   |
| ----------------- | -------- | ----------------------------------------------------------------------------------- | ----------- |
| keygen(102, 0, 4) | 4        | `{item_id: "ITEM001", order_id: "ORD001", product: "Laptop", qty: 1, price: 500}`   | sales.items |
| keygen(102, 0, 4) | 4        | `{item_id: "ITEM002", order_id: "ORD002", product: "Mouse", qty: 2, price: 375}`    | sales.items |
| keygen(102, 0, 4) | 4        | `{item_id: "ITEM003", order_id: "ORD003", product: "Keyboard", qty: 1, price: 320}` | sales.items |

---

## VLog Storage Summary

All these entries are written to vlogs with vlog offsets:

| VLog ID | Offset | store_id | doc_type | Key             | Data Size | Content                              |
| ------- | ------ | -------- | -------- | --------------- | --------- | ------------------------------------ |
| 0       | 0      | 0        | 1        | keygen(0,0,1)   | 45B       | System space metadata                |
| 0       | 100    | 0        | 1        | keygen(0,0,1)   | 60B       | Sales space metadata                 |
| 0       | 200    | 0        | 2        | keygen(0,0,2)   | 80B       | Orders store metadata (store_id=101) |
| 0       | 350    | 0        | 2        | keygen(0,0,2)   | 75B       | Items store metadata (store_id=102)  |
| 1       | 0      | 101      | 4        | keygen(101,0,4) | 120B      | Order document ORD001                |
| 1       | 150    | 101      | 4        | keygen(101,0,4) | 115B      | Order document ORD002                |
| 2       | 0      | 102      | 4        | keygen(102,0,4) | 130B      | Item document ITEM001                |

---

## Key Points

1. **All metadata in store_id=0** - Space/Store/Index definitions all go to the same system store
2. **User data in store_id=101+** - Actual business data lives in separate stores
3. **Bootstrap key** - The `system_store_key` points to the first System space entry, allowing O(1) recovery
4. **Hierarchical namespaces** - Reflect the logical structure: `system.spaces.sales`, `system.stores.sales.orders`
5. **BSON encoded** - Metadata is BSON, actual data is JSON or BSON depending on usage

---

## Current Functions Using store_id=0

- `saveSpace()` - Generates keys with `keygen.Gen(0, 0, 1)`
- `saveStore()` - Generates keys with `keygen.Gen(0, 0, 2)`
- `saveIndex()` - Generates keys with `keygen.Gen(0, 0, 3)`
- `deleteCatalogEntry()` - Scans store_id=0 to find and delete entries
