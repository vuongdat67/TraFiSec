# TraceGuard-DeFi — Pilot (6 case, fork tay trên Anvil)

> This directory preserves engineering pilots. It does not contain the
> paper-grade E4/E5 denominators; see `../eval/results/PAPER_READINESS.md`.

Kế hoạch chi tiết: [`../proposal/pilot.md`](../proposal/pilot.md).

## Kiến trúc code (OOP, 2026-08-11)

Refactor bash → Python-OOP (feedback user 2026-08-11): package `pilot/core/` thay
orchestration của common.sh/mutations.sh; bash còn lại chỉ là wrapper mỏng.

| Module | Vai trò |
|---|---|
| `core/env.py` | .env auto-load (repo root / pilot/) + resolve RPC theo chain — không cần export |
| `core/rpc.py` | RpcClient JSON-RPC (anvil + archive; anvil_set* cho mutation state patches) |
| `core/fork.py` | ForkRunner — vòng đời anvil fork (context manager `with ForkRunner(...)`) |
| `core/replay.py` | Replayer — replay tx lên fork (resend mới, warm-up mid-block, status+gasUsed vs mainnet) |
| `core/outcome.py` | Outcome (EXECUTED_NO_HARM / EXECUTED_HARM / REVERTED) + ReplayResult |
| `core/mutate.py` | Mutation ABC + f_fl / f_orc / f_swap / f_auth — mỗi mutation 1 class, `apply(fork)` |
| `core/runner.py` | CaseConfig + CaseRunner — fidelity → mutations → outcomes.csv thống nhất |
| `core/loss.py` | TraceAnalyzer — loss per-party từ trace (migrate từ loss_calc.py) |
| `core/run_case.py` | CLI chạy 1 case (thay orchestration run.sh) |

**Cách chạy mới (khuyến nghị)** — chạy từ thư mục `pilot/`:

```bash
python -m core.run_case --case <name> --tx <tx_hash> --block <n> \
    --prior <hash_idx0> [--prior <hash_idx1> ...] \
    --mutation f_fl:0xADDR --mutation f_orc:0xORACLE:0xSTUB
```

`.env` tự load bởi **core/env.py** (và `common.sh`) — không cần export:
`cp ../.env.example ../.env` rồi điền key vào `../.env`.

**Cách chạy cũ (bash, đang deprecated):** `bash case<i>_*/run.sh` — vẫn chạy được
(common.sh cũng auto-load .env), nhưng khuyến nghị chuyển sang `python -m core.run_case`.

## Tình trạng (2026-08-10)

| # | Case | Chain | State block (tx−1) | Tx hash | Trạng thái |
|---|---|---|---|---|---|
| 1 | bZx (Feb 2020) flash-loan price manip | mainnet | 9484687 | `0xb5c8bd94...219838` | target verified; replay via 28 warm-up txs |
| 2 | Cream Finance (Aug 2021) oracle manip | mainnet | 13125070 | `0xa9a1b8ea...ffe61e` | **ĐỦ** — fidelity EXECUTED (Δ2.1%), f_fl REVERTED (128573), f_swap REVERTED (1241772) |
| 3 | Euler (Mar 2023) flash-loan + accounting | mainnet | 16817994 | `0xc310a0af...b111d` | run.sh ✓ (chờ RPC) |
| 4 | Radiant (Jan 2024) flash-loan **precision** | arbitrum | 166405685 | `0x1ce7e9a9...7c9b` | run.sh ✓ (chờ ARB RPC) |
| 5 | **WazirX (Jul 2024) Safe key compromise** (governance) | mainnet | 20331564 | `0x48164d3a...e185d` | run.sh ✓ (chờ RPC) |
| 6 | **Arbitrage hợp lệ (Jun 2023)** (hard-negative) | mainnet | 17447510 | `0xe5732cc1...87761c` | run.sh ✓ (chờ RPC) |

> **Case 4 lưu ý:** Radiant Jan 2024 là lỗi **flash-loan precision**, KHÔNG phải admin-key
> → thư mục đã rename `case4_radiant_precision` (trước đây tạm đặt `case4_radiant_auth`).
> Case governance thật là **case 5 (WazirX)** — Safe **4-of-6** (threshold thực = 4, đã verify
> slot 4; Rekt ghi sai 3-of-6) bị lộ signer key (off-chain compromise), đã verify tx hash +
> block + impl (1.3.3) on-chain.

## Setup

- **Foundry 1.7.1** (`~/.foundry/bin`, PATH thêm rồi).
- **Archive RPC BẮT BUỘC** (public RPC không đủ archive cho block cũ) — xem [setup_archive.md](setup_archive.md).
- Case mainnet: `ARCHIVE_RPC`. Case arbitrum: `ARB_ARCHIVE_RPC`. Hoặc `CHAIN_RPC` override mọi thứ.
- RPC keys đặt trong `../.env` (copy `../.env.example`) — **tự động load** bởi common.sh
  và core/env.py, không cần export mỗi lần.
- Chạy shell script bằng **Git Bash thật** (`bash.exe` từ Git for Windows trên
  `PATH`), không dùng WSL `bash`.

## Cấu trúc

```
pilot/
  core/              # Python-OOP (2026-08-11): env, rpc, fork, replay, outcome,
                     #   mutate, runner, loss, run_case — thay common.sh/mutations.sh
  common.sh          # helpers: start_anvil, replay_tx, write_outcome; PATH fix (deprecated dần)
  mutations.sh       # mutation thật: f_fl, f_orc, f_swap, f_auth (revoke/swap) (deprecated dần)
  case_template.sh   # template chạy 1 case
  loss_calc.py       # tính USD loss per-party — đã migrate sang core/loss.py (TraceAnalyzer)
  oraclestub/        # OracleStub.sol + checksummed runtime template/offsets + deploy.sh
  slice_cap.py       # f_swap: cap amountIn 99% trên calldata swap V2/V3 (giữ nguyên)
  setup_archive.md   # hướng dẫn lấy archive RPC key
  case1_bzx_flashloan/run.sh ...
  case2_cream_oracle/run.sh ...
  case3_euler_reentrancy/run.sh ...
  case4_radiant_precision/run.sh ...     # flash-loan precision (arbitrum)
  case5_wazirx_governance/run.sh ...     # Safe key compromise → f_auth
  case6_arbitrage/run.sh ...             # hard-negative control
```

## Quy trình mỗi case

1. Chạy bằng `python -m core.run_case` (khuyến nghị — .env tự load) hoặc `source common.sh`
   + `bash case<i>_*/run.sh` (bash cũ). Không cần export RPC.
2. Fork tại **block tx−1** (`anvil --fork-block-number $((TX_BLOCK-1))`) — state TRƯỚC attack.
3. **Fidelity**: `replay_tx <tx_hash>` — resend tx gốc lên fork, phải EXECUTED (không revert).
4. Với từng mutation trong ground-truth factors: patch state → `replay_tx` → ghi outcome.
5. Ghi `outcomes.csv` + `notes.md`.

> **Kiến trúc replay:** anvil KHÔNG phục vụ `eth_getTransactionByHash` cho block lịch sử
> (kể cả `--from-block`), nên `cast run <hash>` không tìm thấy tx trên fork. Giải pháp:
> `replay_tx` đọc from/to/value/data/gas của tx gốc từ **archive RPC**, rồi `cast send
> --unlocked` (impersonate) lên fork như một **tx mới** với nonce mới. Điều này cũng có
> nghĩa: mutation làm tx revert → gas estimation fail → không có hash → `REVERTED`
> (đúng semantics outcome(S−X)).
>
> **Replay case governance (WazirX):** signatures trong `execTransaction` được tạo trên
> `safeTxHash` có nonce tại block attack → fork block−1 cần `sync_safe_nonce` (+1) trước
> khi replay, nếu không replay REVERTED là artifact của nonce, không phải fidelity fail.
> Xem case5 run.sh + notes.md.

## Outcome classification (pilot tay)

| outcome | định nghĩa |
|---|---|
| EXECUTED_NO_HARM | replay thành công, loss ≤ Lmin, invariant ok |
| EXECUTED_HARM | replay thành công, loss > Lmin / invariant vi phạm |
| REVERTED | tx revert toàn bộ — không tính causal evidence |

`Lmin` pilot default: 100K USD (sẽ pin theo bảng phân vị sau E1–E7).

## Mutation semantics (tóm tắt — chi tiết `research/design_decisions_pilot.md`)

- **f_fl**: remove flash-loan provider (set code 0 + balance 0). Kỳ vọng: outcome ≠ baseline
  — REVERTED (tx chết khi thiếu loan) **hoặc** NO_HARM (loss biến mất, tx vẫn chạy). Cả hai
  đều là CAUSE-evidence; xem `research/design_decisions_pilot.md §3b` (EVM empty-code ≠ REVERT).
- **f_orc**: pin oracle price (snapshot block−1) → kỳ vọng harm biến mất nếu oracle bị thao túng. Dùng `oraclestub/deploy.sh <oracle> <price>`.
- **f_swap**: cap amtIn (manipulation slice) / redirect recipient (routing slice) — theo Δprice.
  - **Cap-slice IMPLEMENT (2026-08-11, case 2):** cắt word2 của `start(uint256 flash,uint256
    amount,uint256 min)` calldata → borrow 0 → REVERTED gas 1.24M (tx chạy gần hết rồi revert).
    CLI: `--mutation f_swap:0` (cap word2→0) hoặc `--mutation f_swap:0x<CALldata>` (override).
    Code: `core/mutate.py start_cap_override()` + Replayer `start_cap` (build override tại `_send`).
  - **Redirect-slice (routing, case 6 arbitrage):** KHÔNG làm ở pilot v1 — call-site-specific
    (top-level calldata là MEV wrapper không decode được; slice swap trong callback Balancer/Aave;
    baseline viol=0 → redirect không đổi CAUSE). Hoãn cho src/replay/ production (xem case6 notes).
- **f_auth**: kênh bằng chứng ĐÚNG cho họ access/compromise là **signature recovery**
  (ecrecover sig blob → tập key thật đã ký). Mọi mutation owner-map trên Safe-family
  (revoke/add/replace, kể cả non-signer) → REVERTED **GS026** (positional signature-check) —
  artifact validation, KHÔNG phải "key đó đã ký". Actor-swap không replay được (signature gắn
  chặt owner-map). Lưu ý: họ **access/compromise là permission-gated, không state-gated** →
  f_fl/f_orc/f_swap vô nghĩa cho case 5 (WazirX); verdict dựa vào recovery + nguồn compromise.

## Đầu ra

- `pilot/case_i/outcomes.csv` — mỗi dòng 1 mutation.
- `pilot/summary.md` — bảng 6 case × outcome (viết sau khi chạy).
- Kết quả là cơ sở viết Method §3 + thiết kế E4 (không phải kết quả E4).

## Lưu ý

- Nếu case nào fork không tái tạo (state phụ, RPC) → ghi `notes.md`, đổi case cùng họ, PASS không tính case đó.
- Mutation revert khắp nơi → đặc tả mutation lỗi (đo revert-rate).
- **Không bao giờ gửi tx lên mainnet** — toàn bộ là fork cục bộ.
