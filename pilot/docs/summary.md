# TraceGuard-DeFi — Pilot Summary (điền sau khi chạy 6 case)

> **Historical diagnostic pilot.** PASS labels below validate parts of the
> replay harness only; they are not corrected fixed-20 fidelity or adjudicated
> causal-accuracy results. See `../eval/results/PAPER_READINESS.md`.

> Template — điền kết quả thực tế sau fidelity + mutation runs.
> PASS tiêu chí pilot: ≥4/6 case có fidelity OK + ít nhất 1 mutation đúng dự đoán
> (outcome(S−X) thay đổi đúng hướng so với ground-truth factor).

## Bảng tổng hợp

| # | Case | Chain | State block | baseline outcome(S) | f_fl | f_orc | f_swap | f_auth | Kết luận |
|---|---|---|---|---|---|---|---|---|---|
| 1 | bZx (Sep 2020) | mainnet | 10852721 | ? (state sai) | – | – | – | – | fork state sai tại 2020 (publicnode) |
| 2 | Cream (Aug 2021) | mainnet | 13125071 (tx index 1 — warm-up 1 prior tx) | **EXECUTED** (fidelity PASS) | **REVERTED** | – (không áp dụng) | – | – | flash swap (UniV2 WISE/WETH) = precondition; oracle Chainlink (giá hằng số) — self-liquidate shape |
| 3 | Euler (Mar 2023) | mainnet | 16817994 | **EXECUTED** (fidelity PASS) | **REVERTED** | – (không áp dụng) | – | – | loan = precondition; donate-to-inflate là factor thật |
| 4 | Radiant (Jan 2024) precision | arbitrum | 166405686 (tx ở 166405687 idx2 — warm-up 2 prior txs) | ? | ? | – | – | – | chờ ARB archive RPC paid |
| 5 | WazirX (Jul 2024) Safe key compromise | mainnet | 20331564 | **EXECUTED** (verify 2026-08-10) | – | – | – | **signature recovery: 4 signers** = threshold; revoke/add → REVERTED GS026 | KEY COMPROMISE |
| 6 | Arbitrage hợp lệ (Jun 2023) | mainnet | 17447510 | **EXECUTED** (mid-block reconstruction) | **REVERTED** | – | – | – | hard-negative; fidelity PASS gas lệch 1.8%; f_fl REVERTED → CAUSE không suy (guard đúng) |

> \* Case 5: "EXECUTED_HARM" = execTransaction rút $235M thành công. Loss xác định bằng
> core/loss.py — TraceAnalyzer, migrate từ loss_calc.py (CLI tương thích) (chuyển token ra
> khỏi Safe). Xem notes.md về giới hạn replay permission-gated.

## Phân loại outcome

- **EXECUTED_NO_HARM**: replay thành công, loss ≤ Lmin (100K), invariant ok.
- **EXECUTED_HARM**: replay thành công, loss > Lmin / invariant vi phạm.
- **REVERTED**: tx revert — không phải causal evidence (không tính CAUSE).

## Kết quả từng case (chi tiết trong case*/outcomes.csv + notes.md)

### Case 1 — bZx
- Fidelity: **chưa chạy được** — publicnode fork block 10852721 (2020) cho balance SAI
  (59.38 ETH vs 4.04 ETH thật — verify eth_getBalance) → state 2020 không chính xác trên
  publicnode; cần RPC archive paid (Alchemy/QuickNode/Tenderly).
- Tx index 99/132 — cần mid-block reconstruction 99 tx nếu chạy được.
- f_fl (disable dYdX): chưa chạy.
- f_swap: chưa chạy.

### Case 2 — Cream
- **Verify 2026-08-11:** hash cũ `0xfa352d...c72a` PHANTOM (không resolve trên 4 RPC).
  Hash đúng từ Rekt: `0xa9a1b8ea...ffe61e` — block 13125071, idx1/257, from `0xce1f4b4f...`
  (nonce 111 khớp), to attack contract `0x38c40427...`. Fork state tại 13125069/70 khớp
  100% (balance+code hash).
- **Mechanism (trace):** `start(500 WETH, 19.48M AMP, 355)` → **Uniswap V2 flash swap**
  (pair `0x21b8065d` = WISE/WETH, uniswapV2Call → 500 WETH) → withdraw WETH → mint
  cWETH → enterMarkets → borrow 19.48M AMP → deploy helper → transfer 9.74e24 AMP →
  helper **self-liquidateBorrow** (cAMP→cWETH) → redeem cWETH → repay flash. Ground-truth
  factors: `f_fl` (flash swap) + `f_swap`.
- **Fidelity: EXECUTED (2026-08-11)** — warm-up idx0 rồi replay, status true,
  gas 1,562,994 vs mainnet 1,531,409 (Δ2.1%) → **PASS**.
- **f_fl: REVERTED (2026-08-11)** — disable Uniswap V2 pair → status false, gas 128,573
  (~8%) → flash swap = precondition (CAUSE không suy trực tiếp).
- **f_swap: REVERTED (2026-08-11)** — cap slice borrow: cắt word2 (amount) của
  `start(500,19.48M,355)` → 0 (CLI `--mutation f_swap:0`). Status false, gas **1,241,772**
  vs mainnet 1,531,409 (~19%) — tx chạy hầu hết rồi revert (borrow 0 không sinh profit để
  repay flash swap). Khác f_fl (chết ngay gas 128k): f_swap chạy gần full → xác nhận
  **borrow slice là thành phần cần** cho attack hoàn tất. REVERTED = precondition (outcome
  guard E4) → không đọc "CAUSE" trực tiếp.
- **f_orc: KHÔNG áp dụng (2026-08-11)** — oracle Cream = ChainlinkPriceOracle
  `0x338EEE1F` (non-proxy), `getUnderlyingPrice(cAMP)` = 17832542795200 HẰNG SỐ ở mọi
  block 65..100; trace chỉ đọc Chainlink reader `0x47Fb2585` (AMP/USD `0xfaaa7460`
  answer 5648000 + USDC/ETH `0xe5bbbdb2` answer 315731990000000 — đều không đổi).
  → KHÔNG phải oracle-manipulation; không build stub (giống case 3 Euler).

### Case 3 — Euler (Mar 2023)
- Fidelity: **EXECUTED** (2026-08-11) — fork block 16817994 OK trên publicnode, replay
  EXECUTED gas ~1.95M khớp mainnet; tx index 0 block 16817996 (không cần mid-block warm-up).
- f_fl (disable Aave V2 LendingPool 0x7d2768de): **REVERTED** (status 0x0, gas 43K ≈ 2%
  mainnet) — tx chết ngay thiếu loan → loan là điều kiện cần (precondition). Theo §3b:
  REVERTED là evidence precondition; CAUSE(f_fl) qua NO_HARM path chưa kiểm được.
- f_orc: **KHÔNG áp dụng** — giá DAI/ETH không đổi qua attack (618764073445216 ở block
  trước/trong/sau) → không phải price-manip; đây là donate-to-inflate accounting.
- **Đọc:** ground-truth factor là donate-accounting (f_fl là tiền điều kiện). Cần phân
  tích donate-path (mutation donate) cho CAUSE đầy đủ.

### Case 4 — Radiant (precision, arbitrum)
- **Verify 2026-08-11:** tx resolve trên `arb1.arbitrum.io/rpc` — block **166405687**,
  idx2/4, status true, from `0x826d5f...dde6d` → Radiant V2 pool `0x39519c...aa8f`.
  TX_BLOCK trong run.sh bị off-by-one (686 → **687**, đã sửa + warm-up idx0/idx1).
- **RPC:** KHÔNG có endpoint public archive Arbitrum nào dùng được (drpc/1rpc/llamarpc/
  publicnode/blastapi/ankr/onfinality đều fail hoặc cần key) → cần **ARB_ARCHIVE_RPC paid**
  (Alchemy/Infura/QuickNode/Ankr) cho fidelity run.
- Fidelity: chờ ARB archive RPC. f_fl: chưa chạy.

### Case 5 — WazirX (governance/access)
- Fidelity: **EXECUTED** (2026-08-10 verify; cần sync nonce Safe 1718→1719 trước replay)
- f_auth(A) revoke-scan từng owner: mọi revoke → **REVERTED GS026** — artifact positional
  signature-check, KHÔNG phải "key đó đã ký" (kể cả revoke non-signer #5/#6 vẫn GS026).
- f_auth(B) actor-swap: **REVERTED GS026** — signature gắn chặt owner-map, không replay được.
- **Kênh bằng chứng đúng = signature recovery:** ecrecover sig blob → **4 signers =
  {#1 0xd967, #2 0xfA54, #3 0x9AF7, #4 0xD83B}** = threshold; #5/#6 không ký.
  Verdict **KEY COMPROMISE** (key bị lộ off-chain), không phải bug code.
- **Nhận xét quan trọng:** attack permission-gated (key compromise off-chain) → state patch
  f_fl/f_orc/f_swap không áp dụng; thay kênh "f_auth-scan outcome-flip" bằng signature
  recovery trong Method §3.3 + E4 (đã cập nhật guide.md).

### Case 6 — Arbitrage hợp lệ (hard-negative)
- Fidelity: **EXECUTED (2026-08-11, mid-block reconstruction)** — tx index 10/132 trong
  block 17447511; replay tx đơn lẻ tại block−1 REVERTED (Aave V2 repay fail); replay
  idx0-9 trước rồi target → EXECUTED, gas 1031334 vs mainnet 1013534 (lệch 1.8%).
- f_fl (disable DssFlash 0x60744434): **REVERTED** (gas 71069 — tx chết thiếu flash-mint).
  Baseline viol(S)=0 → CAUSE không suy được — **guard chống FP arbitrage hoạt động đúng**.
- f_swap: redirect chưa implement (ghi chú).
- **Nhận xét:** baseline viol(S)=0 → dù mutation có đổi outcome, CAUSE vẫn KHÔNG suy được
  (guard chống FP arbitrage). Fidelity PASS xác nhận replay được tx hard-negative.

## Đánh giá

- Số case pass fidelity: **4/6** (case 2 Cream, case 3 Euler, case 5 WazirX, case 6
  arbitrage — 2026-08-11) — case 1 (2020 state sai trên publicnode; cần RPC paid),
  case 4 (tx verified; chờ ARB archive RPC paid — xem notes case 2/4). Đã đủ ngưỡng
  **≥4/6 PASS** để viết Method chốt (theo pilot.md §6).
- Số mutation có outcome khác baseline theo đúng hướng: **5/5 đo được** — case 2 f_fl
  EXECUTED→REVERTED (flash swap precondition) + **case 2 f_swap cap EXECUTED→REVERTED**
  (borrow slice cần để attack hoàn tất; REVERTED = precondition, không tính CAUSE trực tiếp);
  case 3 f_fl EXECUTED→REVERTED (loan precondition); case 5 mọi owner-map mutation
  EXECUTED→REVERTED GS026 (artifact, đúng kỳ vọng outcome guard); case 6 f_fl
  EXECUTED→REVERTED (tx chết thiếu flash-mint — CAUSE không suy vì viol=0, guard chống FP đúng).
- Bài học về mutation spec (điều chỉnh cho Method §3 + E4):
  - **Mid-block reconstruction bắt buộc** khi tx index k>0: replay tx idx0..k−1 rồi target
    (case 6: target ở idx10/132; replay đơn lẻ REVERTED giả).
  - **Đọc status + gasUsed, không chỉ "EXECUTED"** — cast send timeout/empty dễ đọc nhầm;
    so gasUsed với mainnet để phân biệt EXECUTED thật vs revert sớm (case 3 f_fl).
  - **f_orc không áp dụng nếu oracle không bị thao túng** (case 3 Euler: giá DAI/ETH hằng
    số; case 2 Cream: oracle Chainlink `0x338EEE1F`, giá AMP/USD+USDC/ETH đều hằng số qua
    attack) — cần **trace oracle thật** (debug_traceCall `getUnderlyingPrice`) + đọc feed
    pre/post trước khi chọn mutation, không tin mô tả blog.
  - **Archive depth của publicnode ~2.5-3 năm** cho state CHÍNH XÁC (2023+); block 2020
    fork được nhưng state sai → case cũ cần RPC paid.
  - **Verify tx hash nguồn trước khi fork** — hash từ blog/rekt có thể phantom (case 2:
    hash cũ không resolve ở bất kỳ RPC nào; hash thật từ rekt.news, verified on-chain).
  - **Off-by-one block của tx** — verify transactionIndex/block từ receipt trước khi đặt
    TX_BLOCK (case 4: tx ở 687 chứ không 686) + warm-up các tx prior khi index > 0.
  - **f_auth Safe-family: signature recovery là kênh đúng** (đã reconcile guide E4/E7).

## Kết luận cho thiết kế

- **Pilot PASS ngưỡng 4/6 fidelity** — đủ cơ sở viết Method chốt (pilot.md §6).
- Lmin thực nghiệm: ...
- f_fl hiệu quả trên: ...
- f_orc cần stub per-protocol (không generic được): ...
- f_swap chia 2 loại: **cap-slice** (general hóa được — cắt word2 `start()` case 2, REVERTED
  gas 1.24M; CLI `f_swap:0`) vs **redirect-slice** (call-site-specific — case 6 arbitrage
  callback Balancer, hoãn production). Ghi guide.md E4.
- f_auth: với Safe-family multisig, revoke/swap đều REVERTED GS026 (positional sig-check) →
  dùng **signature recovery** (ecrecover sig blob) cho họ access/compromise; xử lý giới hạn
  permission-gated (case 5).

## Refactor Python-OOP (2026-08-11)

- Package `pilot/core/` (env, rpc, fork, replay, outcome, mutate, runner, loss,
  run_case) thay orchestration của `common.sh`/`mutations.sh` — bash chỉ còn wrapper mỏng.
- CLI: `python -m core.run_case --case <name> --tx <hash> --block <n> --prior <hash...>
  --mutation f_fl:0xADDR` (chạy từ `pilot/`; .env auto-load qua core/env.py).
- E2E smoke đã verify: ForkRunner + Replayer + FlashLoanDisable trên **anvil local**
  (không cần archive RPC) — baseline EXECUTED **Δ0.0%** → sau f_fl **REVERTED**.
- Unit tests: `pilot/core/test_core.py` (python -m unittest / pytest).
- `loss_calc.py` → `core/loss.py` (class TraceAnalyzer, CLI tương thích); `slice_cap.py`
  giữ nguyên (đã là tool sạch 1 mục đích).
- Fidelity count không đổi: **4/6** (case 1, 4 chờ RPC paid — xem bảng trên).
