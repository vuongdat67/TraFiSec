# TraceGuard-DeFi — Corpus Attack Set: Schema & Pipeline (Phase 1)

> Mục tiêu Phase 1: xây **attack set** (69+ EVM incidents 2021–2026, verified on-chain
> khi RPC phủ). Đây là nền cho E1 (label attack), E4 (ground-truth factor), E5 (fidelity).
> Hard-negative (50K) + benign (100K) là Phase 2/3 — **KHÔNG làm trong Phase 1**.
>
> Nguyên tắc (user feedback): **ghi nguồn mọi claim**; chỉ dùng hash đã verify trên RPC;
> KHÔNG tin mô tả blog — cơ chế phải trace/đọc state được.

## 1. Định dạng dữ liệu — `corpus/incidents.jsonl`

Mỗi dòng = 1 incident (JSON, UTF-8). Schema chuẩn cho mọi nguồn:

```json
{
  "id": "rekt-cream-2021-10-27",          // slug duy nhất: <nguồn>-<protocol>-<date>
  "source": "rekt",                        // "rekt" | "slowmist" | "defihacklabs" | "bridgetracker" | "manual"
  "source_url": "https://rekt.news/cream-rekt/",
  "protocol": "Cream Finance",
  "date": "2021-10-27",
  "chain": "ethereum",                     // "ethereum" | "bsc" | "arbitrum" | "polygon" | "avalanche" | "other"
  "attack_type": "flash-loan",             // taxonomy: flash-loan | oracle | reentrancy | governance/access |
                                           //           accounting | precision | bridge | token | rug-pull | other
  "loss_usd": 130000000,
  "tx_hashes": ["0x..."],                  // 1+ hash attack (verify on-chain trước khi giữ)
  "block": 13497617,                       // block của tx (nếu biết)
  "class": "attack",                       // "attack" | "hard-negative" (Phase 1: luôn "attack")
  "gt_factors": ["f_fl", "f_orc"],         // ground-truth factor (CAUSE theo E4): f_fl/f_orc/f_swap/f_auth/f_re/f_other
  "notes": "flash loan bơm giá oracle Kyber",  // mô tả cơ chế (từ postmortem/trace)
  "verified": "onchain",                   // "onchain" (tx hash resolve) | "pending" | "blocked" (RPC không phủ)
  "rpc_note": "publicnode archive ~2021+; block 2020 sai"  // nếu verified!=onchain
}
```

**Quy tắc:**
- `tx_hashes` CHỈ giữ hash đã `eth_getTransactionByHash` (hoặc receipt) resolve trên RPC.
  Hash phantom (blog ghi nhưng không resolve) → đánh dấu `verified:"blocked"` + `rpc_note`,
  KHÔNG xoá (giữ để biết cần RPC paid).
- `gt_factors` từ postmortem/trace; nếu chưa rõ → `["unknown"]` + notes. KHÔNG đoán.
- Mỗi incident có source; nếu 2 nguồn trùng incident (vd Rekt + DeFiHackLabs) → **merge 1 dòng**
  (ưu tiên `source` có hash verify), ghi cả 2 URL.

## 2. Nguồn dữ liệu (xếp theo ưu tiên)

| Nguồn | Nội dung | Cách lấy | Ghi chú |
|---|---|---|---|
| **Rekt.news** | 312 incidents leaderboard (2020–2026) + page chi tiết | scrape HTML (`/leaderboard/` → `/xx-rekt/`) | tx hash KHÔNG có trên page leaderboard — cần đọc page chi tiết hoặc tìm postmortem |
| **DeFiHackLabs** (GitHub) | ~700 incidents, **có sẵn tx hash** + PoC source | GitHub API `git ls-remote` / clone / `src/*/README*` | chuẩn nhất để lấy hash; chủ yếu EVM |
| **SlowMist hacked.slowmist.io** | ~500+ incidents | scrape trang | ít tx hash hơn DeFiHackLabs |
| **Bridge-Bug-Tracker** (0xDatapunk) | 13+ bridge bugs kèm "Code to Reproduce" | clone repo | seed cho họ bridge; phải verify hash trên RPC |
| **DeFiScreener dataset** (paper 2026) | 207 incidents (SlowMist+DeFiHackLabs) | đối chiếu bảng trong `md/` | KHÔNG download trực tiếp; dùng làm checklist đối chiếu |

## 3. Pipeline

```
1. scrape_rekt.py        → corpus/raw/rekt_leaderboard.json   (312 rows: protocol, loss, date, url)
                          → corpus/raw/rekt_incidents.json    (312 detail pages: chain + description)
2. fetch_defihacklabs.py → corpus/raw/defihacklabs.json       (300 incidents newest-first, 290/300 có hash)
3. merge.py              → corpus/incidents.jsonl  (dedupe theo protocol+date, hợp 2 nguồn)
4. verify_onchain.py     → corpus/raw/verified_status.jsonl  (eth_getTransactionByHash, KHÔNG sửa gốc)
4.5 apply_verified.py    → merge verified ngược incidents.jsonl + relabel chain theo ground truth
5. label.py              → điền attack_type + gt_factors từ notes/postmortem (manual review còn thiếu)
5.5 apply_manual_patch.py → merge manual_label_patch.jsonl (enrich attack_type từ PoC/postmortem)
6. check.py              → quality gate: đếm, thiếu trường, trùng hash, hash sai
```

- Scripts đặt trong `corpus/scripts/` (Python thuần, dùng `pilot/core/rpc.py`).
- Raw dữ liệu (chưa verify) ở `corpus/raw/`; kết quả sạch ở `corpus/incidents.jsonl`.
- **KHÔNG commit RPC key** — dùng `.env` (core/env.py auto-load).
- **Chain relabel (bước 4.5)**: verify gọi RPC Ethereum mainnet ⇒ hash resolve được = tx
  **chắc chắn là Ethereum**, bất kể chain label từ nguồn. `apply_verified.py` dùng đây làm
  ground truth sửa lại `chain` (56/80 onchain bị nguồn ghi sai là "other"/bsc/arb/avax).

## 4. Mục tiêu & ngưỡng Phase 1

- **≥69 EVM attack incidents** có `class:"attack"`, ưu tiên chain Ethereum/Arbitrum/Base
  (có RPC replay được). BSC/Polygon giữ nhưng đánh dấu `chain` (Stage 2 fork replay cần
  RPC chain tương ứng).
- Phân bố attack_type cân đối: flash-loan / oracle / reentrancy / governance-access /
  accounting / precision / bridge / token.
- Mỗi incident: `verified:"onchain"` HOẶC ghi rõ `verified:"blocked"` + lý do.
- Output kiểm: `python corpus/scripts/check.py` → đếm theo chain/type/verified, phát hiện
  trùng hash, thiếu trường.
- **Filter ở bước merge:** loại entry editorial / non-DeFi khỏi attack set:
  - `the-one-that-got-away` (Rekt #1, 2020-12-20) — placeholder của rekt.news
    (Bitcoin mining theft, không phải DeFi incident), KHÔNG đếm.
  - Mọi protocol có `chain:"solana"`/`"other"` non-EVM → giữ nhưng `verified:"blocked"`
    (RPC mainnet không phủ), để đánh dấu cần RPC khác nếu muốn đưa vào replay.
- **Duplicate cross-source (`duplicate_of`)**: cùng incident có thể xuất hiện ở cả
  DeFiHackLabs (có hash) và Rekt (không hash) với protocol name KHÁC nhau
  (vd `new-market-trading` vs `newmarkettrading-rekt`) → dedupe theo (protocol, date)
  bỏ lọt. Bản Rekt được đánh dấu `"duplicate_of": "<id bản onchain>"` + KHÔNG đếm riêng
  (tránh thổi phồng attack set). Đã áp dụng 2 cặp 2026-05-07/05-25.

## 5. Kết quả chạy 2026-08-11 (Phase 1 attack set)

- **611 incidents** sau merge: ethereum 205, bsc 137, arbitrum 33, polygon 11,
  avalanche 6, optimism 3, fantom 1, other 215 (Rekt không có detail page → chain chưa rõ).
- **80 incidents `verified:"onchain"`** (TẤT CẢ ethereum — ground truth từ RPC mainnet,
  56 bản relabel từ chain sai). Đạt mục tiêu ≥69. Phân bố attack_type sau enrich:
  governance/access 26, accounting 25, oracle 12, token 7, flash-loan 4, precision 3,
  rug-pull 2, bridge 1.
- 448 tx hashes → resolve 125, not-resolve 323. `blocked` 531 = non-EVM (solana/other) +
  BSC/Arbitrum/... (cần RPC chain riêng) + Rekt không có hash + phantom (blog ghi nhưng
  không resolve — 20 ethereum có-hash-blocked, trong đó 3 placeholder `0x0000000000000000...`).
- **Nhãn attack_type (chốt)**: 80/80 onchain có attack_type (0 `"other"`) — 28 record
  notes chỉ là URL alert (PeckShield/TenArmor/Defimon) được agent enrich thủ công bằng cách
  đọc **PoC `_exp.sol` từ DeFiHackLabs** (comment `@Analysis` mô tả root cause) +
  postmortem (UsualMoney/vETH/SummerFi). Patch: `corpus/raw/manual_label_patch.jsonl`
  (28 dòng kèm evidence + sources); apply: `corpus/scripts/apply_manual_patch.py` (bước 5.5).
  gt_factors không có bằng chứng → giữ `["unknown"]` (7 record), KHÔNG đoán.

## 5. Hạn chế RPC (đã verify)

- **publicnode mainnet** archive tốt **~2021+**, state chính xác 2023+; block 2020 (bZx case 1)
  fork được nhưng **balance SAI** → incident pre-2021 cần RPC paid (Alchemy/QuickNode/Tenderly).
- Không phủ **Arbitrum** (case 4 Radiant) → cần `ARB_ARCHIVE_RPC` paid.
- Incident pre-2021 → `verified:"blocked"` (chờ RPC paid), KHÔNG bỏ.

---

## 6. Causal ground truth v1 (paper/E4)

`gt_factors` trong file hiện tại là **legacy mechanism candidate**, được tạo từ
postmortem/heuristic và không tự động tương đương với counterfactual necessity.
Không được dùng trường này để chọn mutation. E4 v2 khám phá candidate chỉ từ
trace/state, tạo verdict trước, rồi mới mở nhãn để chấm.

Nhãn causal dùng cho paper phải nằm trong sidecar
`corpus/annotations/e4_annotations.jsonl` và tuân theo
`corpus/annotations/e4.schema.json`, tách riêng:

- `root_cause_gt`: root cause được adjudicate;
- `enabling_primitives`: flash loan/oracle/swap/auth chỉ là primitive hỗ trợ;
- `intervention_candidates`: phép can thiệp preregistered, không phải kết quả;
- `harm_spec`: victim, token price/decimals, ngưỡng loss để đo cả S và S−X;
- `causal_calls`: call/site cụ thể mà intervention tác động;
- `label_confidence`, `reviewer_votes`, `adjudication`, `evidence`: provenance,
  hai vote độc lập và quyết định cuối.

Một record thiếu `harm_spec` hoặc evidence độc lập vẫn có thể chạy chẩn đoán,
nhưng mutation thành công phải là `EXECUTED_UNKNOWN` và không được tính CAUSE.

*Schema v1.0 — attack inventory + causal sidecar. Cập nhật 2026-08-12.*
