# Case 5 — WazirX (Jul 2024): GnosisSafe signer-key compromise

> Source: [Rekt.news WazirX](https://rekt.news/wazirx-rekt/) + Safe-contracts
> (GS026) + on-chain verify (block 20331565, 4/6 signers — 2026-08-10);
> xem thêm [SOURCES.md](../../SOURCES.md).

## Tóm tắt

- **Chain/Block:** Ethereum mainnet, tx block 20331565 (state fork 20331564).
- **Tx hash:** `0x48164d3adbab78c2cb9876f6e17f88e321097fcd14cadd57556866e4ef3e185d`
  (đã verify on-chain: rekt.news + Etherscan; Safe `0x27fD43BABfbe83a81d14665b1a6fB8030A60C9b4`)
- **Ngày:** 2024-07-18 · **Loss:** ~$235M.
- **Cơ chế:** GnosisSafe **4-of-6** (threshold real = 4, đã verify slot 4) — signer key bị
  chiếm off-chain (phishing/malware trên thiết bị ký). Attacker dựng tx `execTransaction`
  rút quỹ với đủ **4** chữ ký hợp lệ.
- **Ground-truth factors:** `f_auth` (permission). KHÔNG dùng f_fl/f_orc/f_swap.
- **Safe impl:** `0xd9db270c1b5e3bd161e8c8503c55ceabee709552`, `version()` = **"1.3.3"**
  (bản fork 1.3.0, không phải 1.4.1; proxy đọc impl từ slot 0).

## Recovery chữ ký — signer thật (đã verify 2026-08-10)

Phân tích sig blob 260 byte trong `execTransaction` gốc (4 × 65B, Safe 1.3.0 format):
safeTxHash = `0x4e82121a3bc2fb62c0b06ab5fff5ca965ceab4f51cc949c6e50d85ed63e6aa70`
(domainSeparator = `0xa630c4b7...`, nonce 1718, khớp 3 cách tính độc lập).

| Sig | v | Loại | Signer recovered |
|-----|---|------|------------------|
| sig1 | 0x1f (31) | ECDSA eth_sign | **0x9AF78003CecC2383d9D576A49c0C6b17fc34Ae34** (owner #3) |
| sig2 | 0x20 (32) | ECDSA eth_sign | **0xD83b89E261D02B0f2f9E384B44907f8d380E9AF0** (owner #4) |
| sig3 | 0x20 (32) | ECDSA eth_sign | **0xfA54B4085811aef6ACf47D51B05FdA188DEAe28b** (owner #2) |
| sig4 | 0x01 (1) | pre-validated (submitter auto-approve) | **0xd967113224C354600B3151E27Aaba53e3034f372** (owner #1) |

→ **Signers = {#1 0xd967, #2 0xfA54, #3 0x9AF7, #4 0xD83B} = đúng 4 = threshold.**
Owners #5 (0x10F1) và #6 (0xaE64) **không ký**.
- `approvedHashes[0xd967][hash] = 0` tại fork block → sig4 hợp lệ chỉ vì `msg.sender == owner`
  (submitter auto-approve, v==1). Tx `from` = 0xd967. → 0xd967 là submitter.
- checkSignatures pass với `--from 0xd967`, revert GS025 với msg.sender khác (đã verify trên fork).
- **Hàm ý ground truth:** 3 chữ ký ECDSA thật (key #2,#3,#4) + 1 auto-approve (key #1).
  Attack "authorized" bởi đúng threshold key-set → **key compromise off-chain**, không phải bug code.

## Insight quan trọng: permission-gated ≠ state-gated (hệ quả thiết kế mutation)

Từ research + verify:
- Attack WazirX **không được mở khóa bởi state** (không phải bug code, không phải
  giá oracle, không phải pool). Nó được mở khóa bởi **chữ ký hợp lệ từ key bị lộ**.
- Hệ quả:
  1. **Fork-replay nguyên vẹn vẫn EXECUTED** — đúng, vì chữ ký vẫn hợp lệ trên state.
  2. **Mutation state "vá bug" (f_fl/f_orc/f_swap) vô nghĩa** — không có state nào
     "vá được key bị lộ".
  3. **Mutation f_auth là công cụ đúng**, nhưng **mọi đổi owner-set đều REVERTED GS026**
     (phát hiện mới — xem "Giới hạn f_auth cho Safe" bên dưới). Điều này thay đổi
     cách đọc kết quả: REVERTED là **artifact signature-validation**, KHÔNG phải bằng
     chứng "owner đó đã ký".
  4. Kênh bằng chứng chính xác cho họ access/compromise là **signature recovery**:
     đếm + liệt kê key thực sự ký tx (ecrecover từ sig blob) = "điều kiện cần" của
     attack, không phải revoke-scan outcome-flip.

## Giới hạn f_auth cho Safe-family multisig: GS026 là positional signature-check (FINDING)

**Facts (đã verify trên fork 20331564, 2026-08-10):**
- Baseline (6 owners, nonce synced 1718→1719): replay → **EXECUTED**.
- Revoke BẤT KỲ owner nào (kể cả non-signer #5/#6): → **REVERTED GS026**.
- Add owner at head (list + count hợp lệ, getOwners() đọc được 7 owners): → **REVERTED GS026**.
- Replace identity owner #1 (structure/positions/count nguyên vẹn): → **REVERTED GS026**.
- **Replace identity owner #6 (NON-signer, positions nguyên vẹn): → REVERTED GS026** ← decisive.

**Giải thích:** impl 1.3.3 `checkSignatures` yêu cầu recovered signer khớp CHÍNH XÁC
`owners[currentOwner]` tại mỗi bước walk; signature chỉ hợp lệ khi owner-map hoàn toàn
không đổi so với lúc ký. **Bất kỳ mutation nào chạm owner-map (kể cả đổi identity
non-signer) làm mọi chữ ký trong payload mất hiệu lực → REVERTED GS026.**
→ `REVERTED` dưới mọi nhánh f_auth = **artifact validation**, không phải bằng chứng
nhân quả. Outcome guard E4 đã đúng khi không đếm REVERTED là causal.

**Hệ quả thiết kế cho guide.md E7:**
- `f_auth-scan` revoke **không** phải là kênh "tái dựng tập key lộ" qua outcome-flip —
  outcome-flip là artifact. Kênh đúng là **signature recovery** (off-chain, đọc sig blob).
- `f_auth(B) actor-swap` **không thể** "giữ payload, đổi key-set hợp lệ" cho Safe vì
  signature gắn chặt vào owner-map: không có key thật thì không ký lại được payload
  (không có private key). Verdict "compromise ≠ code bug" phải dựa vào **recovery
  + auto-approve rule + nguồn compromise (Rekt/postmortem)**, không phải replay.
- E7 cần cập nhật: kênh chứng minh chuyển từ "outcome-flip under revoke" sang
  "signature recovery + ground-truth compromise source".

## Replay: vấn đề nonce GnosisSafe

- Chữ ký trong `execTransaction` gốc được tạo trên `safeTxHash` chứa nonce = nonce
  TẠI block attack. Fork tại block−1 có nonce thấp hơn 1 → `checkSignatures` fail →
  replay nguyên vẹn REVERTED (artifact của replay, không phải fidelity fail thật).
- Fix trong run.sh: `sync_safe_nonce` — đọc `nonce()` trên fork, tăng +1 vào slot nonce.
- Nếu safe dùng nonces mapping (v1.4.1) → `nonce()` vẫn trả current; setStorageAt cần
  key mapping đúng — run.sh đã dự phòng: nếu không đọc được nonce() thì replay lần 1
  sẽ tiết lộ (ghi lại). Với WazirX (v1.4.1, nonce mapping tại slot 5) cần
  `keccak256(safe + slot5)`. Kiểm tra trên fork trước khi chạy thật.

## Trạng thái

- **2026-08-10 re-run:** fidelity PASS (baseline EXECUTED, sau sync nonce 1718→1719).
- **DIAGNOSTIC (2026-08-10) — layout storage thật là LINKED-LIST, không phải addr→index:**
  - `owners[0xd967] = 0xfA54` (trỏ owner kế tiếp), `owners[0xaE648] = 0x1` (SENTINEL),
    `owners[SENTINEL] = head 0xd967`; `ownerCount=6` (slot 3), `threshold=4` (slot 4) — **Safe 4-of-6**.
  - `sync_safe_nonce` (slot 5 uint256, +1) VERIFIED hoạt động — replay EXECUTED.
  - Version thật v1.3.0-style (nonce plain slot 5), KHÔNG cần nonces-mapping keccak.
- **BUG cũ (đã sửa):** `revoke_owner` zero `owners[X]` → phá linked-list walk → `getOwners()` revert,
  mọi outcome "REVERTED" trong outcomes.csv cũ là **artifact**, không phải bằng chứng.
  `add_owner` ghi `owners[new]=ownerCount+1` (không phải địa chỉ) → list có node 0x0, replay lỗi **GS026**.
  Đã sửa thành: revoke = relink predecessor; add = insert head (đúng OwnerManager).
- **Sau khi fix list đúng, mọi nhánh f_auth vẫn REVERTED GS026 — đây là FINDING thật**
  (positional signature-check, xem phần trên), không phải bug list nữa.
  outcomes.csv hiện giữ 7 dòng linked-list-correct (6 revoke + 1 mode B) — **mọi dòng
  đều REVERTED và là artifact validation**. Bảng kết quả chính thức của case 5 phải
  trình bày theo **signature recovery** (4 signers), KHÔNG theo outcome-flip.

## Kết quả chính thức (2026-08-10, đã verify)

| Kiểm | Kết quả | Ý nghĩa |
|------|---------|---------|
| Fidelity (fork block−1, nonce sync) | **EXECUTED** | replay tái sinh đúng — state phụ đủ |
| Revoke 1 owner (bất kỳ) | **REVERTED (GS026)** | artifact sig-validation, không phải bằng chứng key đó ký |
| Add owner (mode B) | **REVERTED (GS026)** | artifact — actor-swap không chạy được trên Safe |
| Replace identity non-signer (#6) | **REVERTED (GS026)** | proof positional binding — owner-map bất biến |
| Signature recovery | **4 signers = {0xd967,0xfA54,0x9AF7,0xD83B}** | = threshold; #5,#6 không ký |
| Verdict | **KEY COMPROMISE** | ground truth: 3 ECDSA + 1 submitter-auto-approve; attack không thể xảy ra nếu <4 key lộ |

## Điều chỉnh pilot.md

- Case 5 (governance) KHÔNG "fork-replay chữ ký" được theo nghĩa state mutation.
  Cần sửa bảng case-set: **họ access dùng f_auth-scan**, không hứa EXECUTED_NO_HARM.
  Đã ghi trong [pilot.md](../../proposal/pilot.md) §2 (cập nhật).
