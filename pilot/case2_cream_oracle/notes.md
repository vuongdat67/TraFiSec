# Case 2 — Cream Finance (Aug 2021): oracle manipulation

> Source: [Rekt.news Cream](https://rekt.news/cream-rekt/) (verified on-chain 2026-08-11);
> xem thêm [SOURCES.md](../../SOURCES.md).

## Kết quả verify 2026-08-11

### Tx hash gốc trong run.sh KHÔNG resolve
- `0xfa352d6368bbc643bcf9d528ffaba5dd3e826137bc42f935045c6c227bd4c72a`
- Kết quả `cast tx ... blockNumber` trên 4 RPC mainnet (publicnode archive, drpc.org,
  1rpc.io, llamarpc): **tx not found** ở mọi nơi. Hash này không tồn tại trên Ethereum
  mainnet → **hash sai**, cần thay.

### Hash đúng (tìm từ nguồn Rekt, verified on-chain)
- **TX_HASH mới:** `0xa9a1b8ea288eb9ad315088f17f7c7386b9989c95b4d13c81b69d5ddad7ffe61e`
- Block: **13125071**, transactionIndex **1**, status **success** (receipt `true`).
- from = `0xce1f4b4f17224ec6df16eeb1e3e5321c54ff6ede` (attacker đúng theo Rekt —
  nonce 111 khớp trước-tx), to = attack contract `0x38c40427efbaae566407e4cde2a91947df0bd22b`,
  input `0x641ccd83...` (borrow ~195M AMP / 1.17e24 wei).
- → run.sh nên đổi `TX_HASH` sang hash trên; `TX_BLOCK` giữ 13125070 hoặc đổi 13125071
  (state block = block tx − 1; anvil replay hoạt động ở cả 13125069 và 13125070).

### CẢNH BÁO về loại attack (cần kiểm chứng thêm)
- Rekt mô tả sự kiện Aug 2021 này là **reentrancy** qua AMP `_callPreTransferHooks`
  (nested `borrow()` trong `transfer()`), KHÔNG phải oracle manipulation.
- Trace của tx mới (cast run) cho thấy luồng repay + transfer AMP/ETH lớn từ attack
  contract — chưa thấy rõ bơm giá Uniswap. Trước khi chạy pilot nên xác định: nếu đây
  là reentrancy thì ground-truth factor đúng phải là **f_re (reentrancy)** + f_fl,
  không phải f_orc. Hoặc chọn tx khác (1 trong 17 tx exploit) có bơm giá.
- Tránh ảnh hưởng: ghi chú này để đội verify quyết định giữ/đổi framing.

### Fork + state accuracy (mainnet archive publicnode) ✓
- Anvil fork tại 13125069 và 13125070: chạy tốt, `cast block-number` trả đúng block.
- Balance + code hash (keccak) của sender, attack contract, Cream, Uniswap V2 router,
  AMP token tại state block: **khớp 100%** giữa fork và RPC trực tiếp.
- `cast run` tx mới trên fork: **"Transaction successfully executed"**, gas 1,563,076
  → state đáng tin (không giống bZx 2020).
- RPC dùng được: `https://ethereum-rpc.publicnode.com/...` (publicnode mainnet archive).

## Fidelity PASS (2026-08-11, verified status+gasUsed)
- Replay trên fork 13125070 (warm-up idx0 trước) → **EXECUTED** (status `true`),
  gasUsed **1,562,994** vs mainnet **1,531,409** (Δ ~2.1%) — khớp như case 6.
- → **fidelity 4/6** (cases 2, 3, 5, 6).

## Mechanism verify (cast run trace, 2026-08-11)
- `start(500 WETH, 19.48M AMP, 355)` → **Uniswap V2 flash swap** — pair `0x21b8065d`
  = **WISE/WETH** (token0 `0x66a0f676` = WISE, token1 = WETH; factory UniV2
  `0x5C69bEe...`) → `uniswapV2Call` callback nhận 500 WETH → withdraw → mint cWETH
  collateral (`0xD06527D5` cWETH, mint{value:500}) → enterMarkets → **borrow
  19.48M AMP** (cAMP `0x2Db6c82`) + borrow 355 AMP → deploy helper contract
  `0x0ec306D7` (1117 bytes) → transfer 9.74e24 AMP vào helper → helper `794404d1()`
  = **self-liquidation**: `liquidateBorrow(self, 9.74e24 AMP, cWETH)` → redeem cWETH
  (906862180000 cWETH → 187.58 WETH) → helper selfdestruct → repay flash
  (501.55 WETH) → profit = 500 + 355 − 501.55 ≈ 353.45 WETH.
- Oracle (xem mục Oracle bên dưới) = **Chainlink PriceOracle** — `getUnderlyingPrice`
  gọi `0x47Fb2585` (`latestRoundData` trên AMP/USD + USDC/ETH feeds) 4 lần trong tx.
- → attack type: **flash-loan borrow + self-liquidate** (nested borrow trong flash
  callback; oracle KHÔNG bị thao túng). Ground-truth factors: `f_fl` (Uniswap V2
  flash swap) + `f_swap`; **`f_orc` KHÔNG áp dụng** (xem mục Oracle).

## f_swap REVERTED (2026-08-11, verified status+gasUsed)
- **Override:** cắt word2 (amount) của `start(uint256 flash, uint256 amount, uint256 min)`
  calldata gốc `0x641ccd83...` → **borrow = 0** (giữ flash 500 WETH + minReceived 355).
  Implement trong `core/mutate.py start_cap_override()` (selector `0x641ccd83`, đúng 202-char
  calldata), Replayer `start_cap` tự build override tại `_send`.
- **Kết quả:** replay → **REVERTED**, status `false`, gasUsed **1,241,772** vs mainnet 1,531,409
  (Δ~19% — tx chạy hầu hết rồi revert). Borrow 0 → self-liquidation không sinh profit →
  không đủ để repay flash swap → revert cuối.
- **Khác f_fl:** f_fl chết ngay (gas 128k, ~8%) — f_swap chạy gần full rồi revert (gas 1.24M)
  → xác nhận **borrow slice là thành phần cần** cho attack hoàn tất; nhưng REVERTED = precondition
  (outcome guard E4) → không đọc "CAUSE" trực tiếp từ nhánh này.
- **Bug phát hiện:** (a) len calldata đếm nhầm 2+4+96=102 (thực tế 2+8+192=202) → override None
  → f_swap no-op (gas = fidelity 1562994); (b) Replayer build override ở `apply_to_replayer`
  (calldata chưa fetch) → no-op; fix = build tại `_send`. (c) default timeout cast 180s → thỉnh
  thoảng "send fail/timeout" trên publicnode chậm — nâng 240s (chưa hoàn toàn ổn định, chạy tay
  fresh fork + timeout 480 ra kết quả ổn định).

## f_fl REVERTED (2026-08-11, verified status+gasUsed)
- Disable Uniswap V2 pair `0x21b8065d` (setCode 0x + setBalance 0) → replay **REVERTED**,
  status `false`, gasUsed **128,573** (~8% mainnet 1.53M) — tx chết ngay thiếu flash swap.
- → **flash swap = precondition** (giống case 3 Euler loan). CAUSE không suy trực tiếp
  qua nhánh REVERTED; cần mutation khác (f_swap redirect/cap slice) để thấy no-harm.

## f_orc N/A — oracle Chainlink, giá HẰNG SỐ (2026-08-11, verified on-chain)

**Quyết định: KHÔNG build stub, không chạy mutation f_orc** (giống case 3 Euler — xem
case3 notes.md mục Oracle). Cream KHÔNG phải oracle-manipulation attack.

### Bằng chứng on-chain (archive publicnode, block 13125070/71)

1. **Oracle contract của Cream** = `0x338EEE1F7B89CE6272f302bDC4b952C13b221f1d`
   (non-proxy, 24,891 bytes — ChainlinkPriceOracle dạng Compound). Đọc qua comptroller:
   ```
   cast call 0x3d5BC3c8d13dcB8bF317092d84783c2697AE9258 "oracle()(address)" --block 13125070
   → 0x338EEE1F7B89CE6272f302bDC4b952C13b221f1d
   ```
2. **Giá AMP không đổi qua attack** (7 block, đều = 17832542795200):
   ```
   cast call 0x338EEE1F "getUnderlyingPrice(address)(uint256)" 0x2Db6c82... --block {13125065,70,71,75,80,90,100}
   → 17832542795200 [1.783e13]  (giống nhau mọi block)
   ```
   → `17832542795200 / 1e18 = 1.7833e-5 ETH/AMP` = giá AMP/USD ÷ giá ETH/USD
   (khớp chính xác: 0.005648 USD ÷ 3167.24 USD/ETH).
3. **Trace oracle** (`debug_traceCall` trên anvil fork): `getUnderlyingPrice(cAMP)`
   chỉ STATICCALL tới **Chainlink reader `0x47Fb2585D2C56Fe188D0E6ec628a38b74fCeeeDf`**
   4 lần + đọc decimals token USDC/AMP — KHÔNG có Uniswap pool nào trong call path.
4. **2 feed Chainlink (đều KHÔNG đổi)**, round ID cố định:
   ```
   cast call 0xfaaa7460ed59c12e204349766ce73cf5202e6ad6 "latestRoundData()(...)"
   → "AMP / USD", decimals 8, answer 5648000  (round 7568) — pre 13125070 = post 13125071
   cast call 0xe5bbbdb2bb953371841318e1edfbf727447cef2e "latestRoundData()(...)"
   → "USDC / ETH", decimals 18, answer 315731990000000 (round 3535) — pre = post
   ```
5. **Trong chính tx attack** (cast run trace): `getUnderlyingPrice(cAMP)` được gọi 3 lần
   (borrowAllowed, liquidateCalculateSeizeTokens) — mọi lần đọc cùng AMP/USD
   `0x562e80` = 5,648,000 và USDC/ETH `0x11f28151bb180` — giá dùng để tính collateral
   và seize tokens là giá Chainlink cố định.
6. **Không Uniswap pool nào trong oracle storage** (slot 0-3 toàn Chainlink
   reader/proxy: `0x6d5a7597`, `0x197939c1`, `0x9a975fe9`, `0x47fb2585`).

→ **Kết luận:** oracle dùng **Chainlink (giá hằng số)** — mechanism là self-liquidation
chênh giá do AMP/ETH thấp + cWETH collat, KHÔNG phải price-inflate. `f_orc` N/A.
`0x47Fb2585` vẫn để trong run.sh (đọc bởi oracle) nhưng KHÔNG cần stub.

## Việc cần làm (cập nhật 2026-08-11)
1. ✅ Sửa TX_HASH trong run.sh sang hash mới (đã verify + commit).
   - (bổ sung) ✅ Thêm `--mutation f_swap:0` vào run.sh + `--mutation f_swap:0xCALldata` syntax.
2. ✅ Sửa TX_BLOCK 13125070 → **13125071** (tx ở 13125071) + PRIOR_TXS idx0 (warm-up mid-block).
3. ✅ Mechanism đã xác nhận (Uniswap V2 flash swap WISE/WETH + self-liquidate) — FL_PROVIDER điền rồi.
4. ✅ f_fl chạy xong: **REVERTED** (precondition) — ghi outcomes.csv.
5. ✅ **f_orc: KHÔNG áp dụng** — oracle Chainlink, giá AMP hằng số (by chứng 6 ý trên).
   Không build stub; không ghi dòng outcomes.csv (giống case 3 f_orc N/A).
6. ✅ OOP pipeline chạy lại fidelity + f_fl trên RPC thật: EXECUTED Δ2.1% + f_fl REVERTED
   (khớp kết quả cũ) — refactor OK. Ghi chú bug `--out` string/Path ở mục dưới.

## Bug OOP wrapper (2026-08-11) — `--out` string vs Path
- `run.sh` truyền `--out "$SCRIPT_DIR"` (string) → `CaseRunner.__init__` làm
  `self.out_dir / "outcomes.csv"` (pathlib Path) + `self.out_dir.mkdir()` →
  **TypeError: unsupported operand for /: 'str' and 'str'** → run.sh exit 1.
- Không sửa `core/*.py` theo constraint — chạy vòng với `--out` bỏ đi (default Path
  `pilot/case_cream_oracle/`), kết quả khớp; sau đó xóa thư mục rác đó.
- **Fix đề xuất:** trong `core/run_case.py` đổi `out_dir=args.out` →
  `out_dir=Path(args.out) if args.out else None` (import pathlib) — hoặc `CaseRunner`
  tự `Path(out_dir)` nếu là str. (Để lại cho refactor batch sau — không sửa ở đây.)
