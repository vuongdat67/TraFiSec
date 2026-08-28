# Case 6 — Honest arbitrage (Jun 2023): hard-negative control

> Source: on-chain verify (block 17447511 tx 0xe5732c...87761c; positional analysis
> 2026-08-11); xem thêm [SOURCES.md](../../SOURCES.md).

## Tóm tắt

- **Chain/Block:** Ethereum mainnet, tx block 17447511 (state fork 17447510).
- **Tx hash:** `0xe5732cc1772af6bf6e7f89af0ba957cc3b5403aa3d30bc73f56a07a59987761c`
  (verify on-chain: MEV bot, 2023-06-10).
- **Cơ chế:** flash-mint $200M DAI qua MakerDAO DssFlash (`0x60744434d6339a6B27d73d9eDa62B6F66a0A04fA`)
  → Aave V2 supply + borrow WETH → Balancer wstETH/stETH swap → repay atomically.
  Net profit ~$3.24. KHÔNG có victim.
- **Vai trò:** negative control cho RQ2 — "replay phân biệt được attack/arbitrage?"
- **Ground-truth factors:** `f_fl` (DssFlash) + `f_swap` (routing slice). KHÔNG có `f_orc`
  (giá không bị thao túng).

## Kỳ vọng (hard-negative)

| Mutation | Baseline | outcome(S−X) | Đọc |
|---|---|---|---|
| — | EXECUTED_NO_HARM | — | loss ≤ Lmin, không victim |
| f_fl (disable DssFlash) | NO_HARM | REVERTED (tx chết thiếu loan) **hoặc** NO_HARM | nếu NO_HARM → xem xét: arbitrage không cần loan → KHÔNG CAUSE (đúng) |
| f_swap (redirect) | NO_HARM | NO_HARM | không có victim → redirect không tạo harm |

**Điểm mấu chốt:** không mutation nào được tạo ra `EXECUTED_HARM` hoặc một `NO_HARM`
gây nhầm thành CAUSE. CAUSE đòi `viol(S)=1` — baseline arbitrage có `viol(S)=0`, nên
dù outcome(S−X) có đổi, CAUSE vẫn không được suy (đây chính là guard chống FP).

## Trạng thái

- run.sh ✓ (chờ archive RPC).
- `FL_PROVIDER` = DssFlash (đã verify); xác nhận lại code/balance trên fork trước run thật.
- `f_swap` (redirect replayer) chưa implement ở pilot v1 → run.sh ghi note + skip;
  bổ sung khi làm replayer redirect (design_decisions §3).

## Finding 2026-08-11 — replay fidelity fail: mid-block state dependency

**Kết quả fidelity:** `baseline outcome(S) = REVERTED` khi fork block−1 và replay tx đơn lẻ.
Chẩn đoán cho thấy KHÔNG phải do archive window (publicnode fork được tận block 2023 —
verify: fork 17447510 thành công, balance/storage đọc đúng). Nguyên nhân là **mid-block
state dependency**:

- Tx arbitrage nằm ở **index 10/132** trong block 17447511 → state trước tx không phải
  state cuối block 17447510, mà là state SAU 10 tx đầu của block 17447511 (MEV bot
  tx trong cùng block, phụ thuộc thay đổi pool state của các tx đi trước).
- Replay trên fork tại block−1 (trạng thái đầu block) bỏ qua 10 tx đó → Aave V2
  `LendingPool` trả về state khác → call cuối `repay` (WETH `transferFrom`) revert.
  Trace: `0x7d2768de -> 0xc02aaa39 sel=0x23b872dd [ERROR: execution reverted]` trong
  `sel=0x573ade81` (repay).
- Ngoài ra: các tx prior (idx1-9) replay trên fork báo SEND-FAIL/`status=none` vì
  **publicnode archive chậm** — từng call `cast tx` fetch nhiều storage slot qua RPC
  khiến `cast send` chạm timeout confirm mặc định. Cần `--timeout 180` trở lên, và
  dùng receipt mainnet `gasUsed` để đối chiếu (không dùng `cast send` status khi nó
  timeout — timeout ≠ revert).

**Ý nghĩa cho pilot (spec):** case replay cần có bước **mid-block reconstruction**:
fork tại block−1, replay LẦN LƯỢT các tx index 0..k−1 của block tx (theo thứ tự, từ
impersonate từng `from`), RỒI mới replay tx target ở index k. Đây là khác biệt quan
trọng với case 5 (WazirX) — Safe tx nằm ở vị trí không phụ thuộc state trong block.
Ghi vào guide.md E5 + design_decisions: "fidelity replay cần warm-up mid-block khi
tx target index > 0".

**Kết quả chính thức (2026-08-11):** mid-block reconstruction thành công — replay
idx0-9 rồi target → **baseline outcome(S) = EXECUTED**, gasUsed 1031334 vs mainnet
1013534 (lệch 1.8%). Fidelity PASS cho hard-negative case 6. f_fl mutation đang chạy
(kết quả ghi vào outcomes.csv).

## f_swap redirect — feasibility (2026-08-11)

**Kết luận: KHÔNG làm ở pilot v1 — hoãn cho src/replay/ production.** Lý do:

1. **Top-level calldata là wrapper multi-layer** của MEV bot contract (`0x7d32c907...`),
   selector `0x011e0715` + inner `0xa45cffe9` **không nằm trên 4byte** (chưa được decode
   công khai) — không decode bằng cast được. Định dạng: `abi.encodePacked(DssFlash,
   DssFlash, selector_flashMint, args)` → `flashMint(0x60744434, DAI, 200M, callbackData)`.
   Slice swap (Balancer/Aave) nằm TRONG callbackData (offset 0x80+), không ở top-level.
2. **Redirect recipient = đổi đích swap trong callback** — cần parse callback data + trace
   để tìm `swapType`/`assetOut` của Balancer `batchSwap` → đổi assetOut về token gốc. Đây là
   call-site-specific analysis, không general hóa được như cap word2 của `start()` (case 2).
3. **Không đổi được CAUSE logic:** baseline case 6 có `viol(S)=0` (không victim). Dù redirect
   làm tx khác đi (vd ETH nhận tại chỗ thay vì chuyển), baseline vẫn NO_HARM → redirect không
   tạo harm → đọc CAUSE KHÔNG hợp lệ. Negative-control đã đủ bằng f_fl REVERTED + fidelity
   EXECUTED (xem bảng dưới).
4. **`cast run --trace-depth 3` chạy trên archive chậm** (publicnode) → timeout 3m. Cần RPC
   paid + `debug_traceTransaction` (anvil) để phân tích slice chính xác — là việc của
   production (src/replay/ + E4 multi-factor).

→ Ghi trong guide.md E4: f_swap phân loại thành **cap-slice** (có thể general hóa — case 2
`start()` word2) vs **redirect-slice** (call-site-specific — case 6 Balancer callback). Pilot v1
chỉ implement cap; redirect được hoãn có chủ đích vì không có harm oracle và
không thuộc frozen claim scope.

## Kết quả chính thức (bảng)

| Mutation | Baseline | outcome(S−X) | Đọc |
|---|---|---|---|
| — | **EXECUTED** (mid-block reconstruction) | — | fidelity PASS, gas lệch 1.8% |
| f_fl (disable DssFlash) | EXECUTED | **REVERTED** (gas 71069) | tx chết thiếu flash-mint; baseline viol=0 → CAUSE KHÔNG suy — guard chống FP arbitrage ĐÚNG |
| f_swap (redirect) | EXECUTED | skip (redirect chưa implement) | — |

**Ghi chú bổ sung:** publicnode fork được tận block 2023 (verify 2026-08-11) — kết luận
"archive window ~2 năm" trước đó SAI. Block 2020 (bZx case 1) fork được nhưng balance
sai (59 ETH vs 4.04 ETH thật) → archive depth của publicnode giới hạn ~2.5-3 năm
cho STATE chính xác; chỉ block ≥ ~2023 cho state chuẩn.
