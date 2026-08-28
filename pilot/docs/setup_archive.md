# Pilot — Cần Archive RPC (bắt buộc)

## Vì sao
Các case pilot fork ở **block cũ** (bZx 2020: 10.85M, Cream 2021: 13.1M, Euler 2023: 16.8M, Radiant 2024: 166M):
- **Public RPC không có archive data** — verified 2026-08-10: publicnode (403 archive token), drpc (403), 1rpc (historical state not available), llamarpc (403), flashbots (state pruned).
- Anvil cần đọc state cũ → **phải có RPC archive trả phí**.

## Cách dùng nhanh (2026-08-11+)
```bash
# .env ở repo root TỰ ĐỘNG load (không cần export mỗi lần):
cp ../.env.example ../.env     # rồi điền key vào ../.env

# Cách mới (khuyến nghị) — Python-OOP, tự load .env qua core/env.py:
cd pilot
python -m core.run_case --case cream --tx <hash> --block <n> \
    --prior <hash_idx0> --mutation f_fl:0xADDR

# Cách cũ (bash) — common.sh cũng tự load ../.env:
bash case2_cream_oracle/run.sh # common.sh đọc ../.env
```

## Cách lấy key (chọn 1)

### 1. Alchemy (khuyên dùng — free tier có archive Ethereum mainnet)
1. Vào [alchemy.com](https://alchemy.com) → Sign up (free).
2. Dashboard → **Create App** → chain Ethereum, network **Mainnet**.
3. Lấy **HTTP endpoint**: `https://eth-mainnet.g.alchemy.com/v2/<KEY>`.
4. Free tier có archive access. Chạy:
   ```bash
   export ARCHIVE_RPC="https://eth-mainnet.g.alchemy.com/v2/<KEY>"
   bash pilot/case1_bzx_flashloan/run.sh
   ```

### 2. QuickNode (paid, archive chuẩn)
1. [quicknode.com](https://quicknode.com) → tạo endpoint Ethereum mainnet (chọn archive = add-on).
2. Lấy HTTPS endpoint.

### 3. DRPC / Allnodes (archive token riêng)
- drpc.org: tạo endpoint, chọn "Archive".
- allnodes.com: publicnode yêu cầu personal token cho archive.

## Test nhanh trước khi chạy pilot
```bash
# mình đã viết sẵn test; sau khi có key:
export ARCHIVE_RPC="https://eth-mainnet.g.alchemy.com/v2/<KEY>"
bash -c 'cd /f/KhoaLuan/TraceGuard-DeFi/pilot && source common.sh && start_anvil 10852715 && echo FORK_OK && stop_anvil'
# kỳ vọng: "FORK_OK"
```

## Ghi chú
- **Không commit key** vào git/repo; dùng env var `ARCHIVE_RPC`.
- Mỗi fork ~1–3 phút đầu (fetch state); các mutation sau đó nhanh hơn.
- Nếu muốn chạy case Arbitrum (Radiant) → cần **Arbitrum archive RPC** riêng (`https://arb-mainnet.g.alchemy.com/v2/<KEY>`).
