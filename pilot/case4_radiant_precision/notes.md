# Case 4 — Radiant Capital (Jan 2024): flash-loan precision bug

> Source: [Rekt.news Radiant](https://rekt.news/radiant-rekt/) + DeFiHackLabs PoC
> (verified on-chain 2026-08-11); xem thêm [SOURCES.md](../../SOURCES.md).

## Tóm tắt

- **Chain/Block:** Arbitrum, tx block 166405686 (state fork 166405685).
- **Tx hash:** `0x1ce7e9a9e3b6dd3293c9067221ac3260858ce119ecb7ca860eac28b2474c7c9b`
- **Loại attack:** flash-loan precision/rounding bug (DeFiHackLabs PoC) — khai thác làm
  tròn trong accounting borrow/repay, repay flash loan và giữ lại lợi nhuận.
- **Ground-truth factors:** `f_fl` (flash loan là yếu tố tiền điều kiện).
- **RPC cần:** `ARB_ARCHIVE_RPC` (không phải `ARCHIVE_RPC`).

## Lưu ý đặt tên

- Thư mục được rename từ `case4_radiant_auth` → `case4_radiant_precision` để tránh nhầm
  với case governance (case 5 — WazirX). Radiant Jan 2024 KHÔNG phải attack admin-key;
  đó là bug precision/rounding.

## Trạng thái

- run.sh ✓ (chờ ARB archive RPC).
- `FL_PROVIDER` để trống → điền sau fidelity run đầu bằng `cast run --trace` (xem run.sh).

## Verify 2026-08-11 (tx hash + readiness)

### Tx hash RESOLVE ✓ (trên Arbitrum, chứ không phải mainnet)
- `0x1ce7e9a9e3b6dd3293c9067221ac3260858ce119ecb7ca860eac28b2474c7c9b`
- `cast tx blockNumber` trên **mainnet publicnode → tx not found (đúng, tx là Arbitrum)**;
  trên `https://arb1.arbitrum.io/rpc` (official Arbitrum RPC): **block 166405687**,
  transactionIndex 0x2, status `true`, from `0x826d5f4d8084980366f975e10db6c4cf1f9dde6d`,
  to `0x39519c027b503f40867548fb0c890b11728faa8f` (Radiant V2 lending pool), type-2 EIP-1559.
- **Lỗi lệch block trong run.sh:** TX_BLOCK đang để 166405686, nhưng tx thực ở
  **166405687** → TX_BLOCK phải sửa thành 166405687, STATE_BLOCK = 166405686.
  Block 166405686 vẫn tồn tại (hash `0x52b8...4880`).

### RPC Arbitrum archive — CHƯA có endpoint public dùng được
- `arb1.arbitrum.io/rpc` (official): KHÔNG phải archive — anvil fork tại 166405686 fail:
  `missing trie node ... state is not available`.
- Các endpoint thử và kết quả (không endpoint nào đạt archive depth):
  - arbitrum.llamarpc.com — DNS fail; arbitrum.drpc.org / 1rpc.io/arb — tx not found
    + missing trie node (không archive); rpc.ankr.com/arbitrum — cần API key;
    arbitrum-rpc.publicnode.com — tx not found (không archive); arbitrum-mainnet
    public.blastapi.io — missing trie node; api.onfinality.io — 429 cần key;
    omniatech / chainstacklabs / stackup — 521/DNS fail.
- Kết luận: **cần ARB_ARCHIVE_RPC trả phí** (Alchemy/Infura/QuickNode/Ankr key,
  hoặc ArchiveNode tư nhân) để chạy fidelity; chưa tìm được public archive miễn phí.

## Việc cần làm (cập nhật 2026-08-11)
1. ✅ Sửa TX_BLOCK trong run.sh: 166405686 → **166405687** (state block 166405686)
   + PRIOR_TXS idx0+idx1 (warm-up mid-block — tx index 2/4).
2. Cấu hình `ARB_ARCHIVE_RPC` (archive trả phí) trước fidelity run.

## Mở rộng tiềm năng

Nếu muốn 1 case Radiant **governance** (Oct 2024, ~$50M multisig key compromise, các
signer trên 2 thiết bị bị nhiễm malware), đó là case riêng — không gộp vào case 4.
Hiện case governance chính trong pilot là **WazirX (case 5)**.
