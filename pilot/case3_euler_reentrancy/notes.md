# Case 3 — Euler Finance (Mar 2023): flash-loan + accounting manipulation

> Source: [Rekt.news Euler](https://rekt.news/euler-rekt/) (verified on-chain 2026-08-11);
> xem thêm [SOURCES.md](../../SOURCES.md).

## Tóm tắt

- **Chain/Block:** Ethereum mainnet, tx block **16817996** (state fork 16817994 — block−1).
  LƯU Ý: run.sh cũ ghi `TX_BLOCK=16817995` — thực tế tx ở block 16817996 (đã verify).
- **Tx hash:** `0xc310a0affe2169d1f6feec1c63dbc7f7c62a887fa48795d327d4d2da2d6b111d`
  (index 0 trong block — state-independent, không cần mid-block warm-up).
- **From/To:** `0x5F259D0b...` → `0xeBC29199...` (Euler Deployer).
- **Cơ chế:** flash loan (Aave V2 LendingPool `0x7d2768de` flashLoan) → donate để inflate
  EToken balance → mint bad debt → repay self-debt. ~$197M loss.
- **Ground-truth factors:** `f_fl` (flash loan) + `f_orc` (oracle/accounting).
- **Vai trò:** attack case cho RQ2/RQ4 — chứng minh replay bắt được attack state-gated.

## Kết quả (2026-08-11, publicnode archive)

| Mutation | Baseline | outcome(S−X) | Đọc |
|---|---|---|---|
| — | **EXECUTED** (fidelity PASS) | — | tx tái tạo nguyên vẹn trên fork 16817994 |
| f_fl (disable Aave V2) | EXECUTED | **REVERTED** (gas 43K ≈ 2% mainnet) | loan = điều kiện cần (precondition) — xem phân tích dưới |
| f_orc (pin oracle) | EXECUTED | **N/A** | giá DAI/ETH không đổi qua attack — KHÔNG phải price-manip (xem mục Oracle) |

**Fidelity PASS** — case 3 fork được trên publicnode (block 16817994 nằm trong archive
depth), replay EXECUTED, gas ~1.95M khớp mainnet.

## Finding f_fl — REVERTED khi disable Aave V2 (loan = điều kiện cần)

Disable Aave V2 LendingPool (setCode 0x + setBalance 0) → replay **REVERTED**
(status 0x0, gas 43145 = ~2% mainnet 1.95M — tx chết ngay sau khi flashLoan fail).
Phân tích:

1. **Ghi chú đọc kết quả lần đầu SAI:** script đầu đọc `cast send` JSON thiếu field
   `status` (timeout/empty) → đọc nhầm "EXECUTED". Verify lại bằng status 0x0 + gasUsed
   43K cho thấy tx **revert sớm**. Bài học: luôn đọc `status` + so gasUsed với mainnet.
2. **setCode 0x trên Aave V2** — call `flashLoan` tới address không code = success no-op
   trả về rỗng (design_decisions §3b). Nhưng ở đây Aave V2 có **logic balance check**
   trong pool (không phải code rỗng nữa — pool là proxy delegatecall tới logic) →
   `flashLoan` fail → tx chết. REVERTED = **loan là tiền điều kiện** (precondition).
3. **Đọc đúng theo §3b:** REVERTED (mutation làm tx sập) → loan là necessary condition
   cho execution. Theo outcome guard E4: REVERTED không tính CAUSE trực tiếp (viol=0
   do revert là trivial); cần mutation thay đổi **outcome harm** (vd pin oracle để
   harm biến mất nhưng tx chạy) mới cho CAUSE. f_orc là hướng kiểm tiếp theo.
4. Euler attack là **donate-to-inflate**: attacker donate DAI vào EToken → inflate
   balance → mint bad debt. Flash loan là nguồn vốn tạm BẮT BUỘC (tx không chạy nổi
   thiếu nó). Cần phân tích donate-path để xác định factor thật (donate hay loan).

## Oracle

- Oracle feed trong trace: Chainlink **DAI/ETH** `0x773616e4d11a78f511299002da57a0a94577f1f4`
  (aggregator; proxy `0x158228e0...`; selector `0x50d25bcd` = `latestAnswer()`), đọc bởi
  Euler Protocol `0x27182842` — dùng cho liquidation checks.
- **f_orc KHÔNG áp dụng (finding 2026-08-11):** giá DAI/ETH **không đổi** trước/trong/sau
  attack (618764073445216 ở cả 3 block 16817994/96/18000) → đây KHÔNG phải price-manipulation
  attack; oracle không bị thao túng. Ground-truth factor là **donate-to-inflate accounting**
  (f_fl là tiền điều kiện — REVERTED khi disable). EXPECTED_FACTORS của case 3 cần sửa:
  `f_fl` (đã chạy) — bỏ `f_orc`; thêm donate-path mutation nếu implement được.
- Ghi chú: OracleStub hiện chỉ handle `latestRoundData()` (0xfeaf968c) + `answer()` —
  cần thêm `latestAnswer()` (0x50d25bcd) nếu muốn pin oracle cho case dùng selector này.

## Trạng thái

- run.sh ✓ fidelity PASS; TX_BLOCK=16817996 (đã sửa), FL_PROVIDER = Aave V2 (đã sửa).
- f_fl: **REVERTED** (loan = precondition — đã verify status 0x0 + gasUsed 43K).
- f_orc: **KHÔNG áp dụng** (giá hằng số — không phải price-manip). EXPECTED_FACTORS trong
  run.sh đã sửa thành `f_fl` (bỏ `f_orc`).
- Donate-path mutation (factor thật) chưa implement — để spec v2.

## Correction / verification 2026-08-22

- Euler source audit: không có error registry số kiểu `"48"` trong
  `euler-legacy-xyz/euler-contracts`; Euler dùng string literal như
  `e/insufficient-balance` và `e/collateral-violation` trực tiếp trong Solidity.
- `Error("48")` trong lần chạy r6 không được diễn giải là Euler error. Quan trọng hơn,
  f_fl khi đó còn dùng nhầm selector dYdX `a67a6a45` cho Aave V2. Adapter đã sửa để
  lấy selector từ trace; Euler/Aave V2 dùng `ab9c4b5d`.
- Chạy lại r7: f_fl dừng đúng ở flash-loan entrypoint `ab9c4b5d`, `REVERTED`, gas
  `43,320`, `out_of_gas=false`, `revert_data=null`. Guard mutation cố ý trả
  `REVERT(0,0)`, nên đây là **mutation-induced empty revert**, không phải
  `e/insufficient-balance` hay Euler error. Theo removal signature vẫn giữ
  `INCONCLUSIVE-revert`; không dùng `Error("48")` làm bằng chứng.
- f_health_check vẫn `CAUSE-NECESSARY-blocking`: `Error("e/collateral-violation")`,
  gas `1,542,703`, same-block/proof/per-tx gates pass.
- Bytecode live của EToken implementation `0xbb0d...4c0a` tại block 16817995 và
  latest có cùng SHA-256 `bcaaa3e0...acc6d4fb`; nó là runtime vulnerable, không phải
  patched PR runtime. Fixture hiện tại là source-compiled counterfactual và chưa
  được byte-level xác minh với một live patched deployment.
