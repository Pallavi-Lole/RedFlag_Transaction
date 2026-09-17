-- ============================================================
-- RedFlag — The Fraud Files
-- Fraud Detection Engine using SQL
-- Student: Pallavi Lole
-- Batch: DA-DS-july
-- ============================================================

USE redflag;

-- ============================================================
-- P1: Velocity Fraud
-- Rule: 30 or more transactions by the same user
--       on the same calendar day
-- Finding: 23 suspicious user-days detected.
-- ============================================================

SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS daily_txn_count
FROM transactions
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY daily_txn_count DESC;


-- ============================================================
-- P2: Round-Amount Clustering
-- Rule: User has 15 or more transactions at common
--       round amounts.
-- Finding: 2 suspicious users detected.
-- ============================================================

SELECT
    user_id,
    COUNT(*) AS round_amount_txns
FROM transactions
WHERE amount IN (100, 200, 500, 1000, 2000, 5000, 10000)
GROUP BY user_id
HAVING COUNT(*) >= 15
ORDER BY round_amount_txns DESC;


-- ============================================================
-- P3: Card Testing
-- Rule: 30 or more transactions below ₹10 by the same
--       user on the same day.
-- Finding: 12 suspicious user-days detected.
-- ============================================================

SELECT
    user_id,
    DATE(txn_time) AS attack_date,
    COUNT(*) AS small_txn_count
FROM transactions
WHERE amount < 10
GROUP BY user_id, DATE(txn_time)
HAVING COUNT(*) >= 30
ORDER BY small_txn_count DESC;


-- ============================================================
-- P4: Failed-Then-Succeeded
-- Rule: FAILED transaction followed by SUCCESS transaction
--       for same user and amount within 2 minutes.
-- Finding: 25 suspicious users detected.
-- ============================================================

SELECT COUNT(*) AS suspect_users
FROM (
    SELECT DISTINCT t1.user_id
    FROM transactions t1
    JOIN transactions t2
        ON t1.user_id = t2.user_id
        AND t1.amount = t2.amount
        AND t2.txn_time > t1.txn_time
        AND t2.txn_time <= DATE_ADD(t1.txn_time, INTERVAL 2 MINUTE)
    WHERE t1.status = 'FAILED'
      AND t2.status = 'SUCCESS'
) AS flagged;


-- ============================================================
-- P5: Odd-Hour Concentration
-- Rule: At least 30 transactions and at least 80% occur
--       during hours 02:00, 03:00 or 04:00.
-- Finding: 0 suspicious users detected.
-- ============================================================

SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(
        CASE
            WHEN HOUR(txn_time) IN (2, 3, 4) THEN 1
            ELSE 0
        END
    ) AS odd_hour_txns,
    ROUND(
        100.0 * SUM(
            CASE
                WHEN HOUR(txn_time) IN (2, 3, 4) THEN 1
                ELSE 0
            END
        ) / COUNT(*),
        2
    ) AS odd_hour_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 30
   AND SUM(
       CASE
           WHEN HOUR(txn_time) IN (2, 3, 4) THEN 1
           ELSE 0
       END
   ) / COUNT(*) >= 0.80
ORDER BY odd_hour_percentage DESC;


-- ============================================================
-- P6: Mule Accounts
-- Rule: CREDIT followed by DEBIT of at least 70% of the
--       credit amount within 30 minutes.
-- Finding: 29 suspicious users detected.
-- ============================================================

SELECT COUNT(*) AS suspect_users
FROM (
    SELECT DISTINCT c.user_id
    FROM transactions c
    JOIN transactions d
        ON c.user_id = d.user_id
        AND d.txn_type = 'DEBIT'
        AND d.txn_time > c.txn_time
        AND d.txn_time <= DATE_ADD(c.txn_time, INTERVAL 30 MINUTE)
        AND d.amount >= 0.70 * c.amount
    WHERE c.txn_type = 'CREDIT'
) AS flagged;


-- ============================================================
-- P7: Refund Abuse
-- Rule: At least 20 transactions and more than 40% are refunds.
-- Finding: 13 suspicious users detected.
-- ============================================================

SELECT
    user_id,
    COUNT(*) AS total_txns,
    SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END) AS refund_txns,
    ROUND(
        100.0 * SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END)
        / COUNT(*),
        2
    ) AS refund_percentage
FROM transactions
GROUP BY user_id
HAVING COUNT(*) >= 20
   AND SUM(CASE WHEN txn_type = 'REFUND' THEN 1 ELSE 0 END)
       / COUNT(*) > 0.40
ORDER BY refund_percentage DESC;


-- ============================================================
-- P8: Merchant Collusion
-- Rule: Top 5 users account for more than 60% of a merchant's
--       total transactions.
-- Finding: 15 suspicious merchants detected.
-- ============================================================

WITH user_merchant_counts AS (
    SELECT
        merchant_id,
        user_id,
        COUNT(*) AS user_txns
    FROM transactions
    GROUP BY merchant_id, user_id
),
ranked_users AS (
    SELECT
        merchant_id,
        user_id,
        user_txns,
        ROW_NUMBER() OVER (
            PARTITION BY merchant_id
            ORDER BY user_txns DESC
        ) AS rn
    FROM user_merchant_counts
),
merchant_totals AS (
    SELECT
        merchant_id,
        COUNT(*) AS total_txns
    FROM transactions
    GROUP BY merchant_id
)
SELECT
    r.merchant_id,
    SUM(r.user_txns) AS top5_txns,
    m.total_txns,
    ROUND(
        100.0 * SUM(r.user_txns) / m.total_txns,
        2
    ) AS top5_percentage
FROM ranked_users r
JOIN merchant_totals m
    ON r.merchant_id = m.merchant_id
WHERE r.rn <= 5
GROUP BY r.merchant_id, m.total_txns
HAVING SUM(r.user_txns) / m.total_txns > 0.60
ORDER BY top5_percentage DESC;


-- ============================================================
-- P9: Just-Under-Threshold
-- Rule: User has at least 10 transactions of exactly ₹9,999.
-- Finding: 6 suspicious users detected.
-- ============================================================

SELECT
    user_id,
    COUNT(*) AS threshold_txns
FROM transactions
WHERE amount = 9999.00
GROUP BY user_id
HAVING COUNT(*) >= 10
ORDER BY threshold_txns DESC;


-- ============================================================
-- P10: Dormant-Then-Active
-- Rule: Gap of at least 90 days followed by at least
--       15 subsequent transactions.
-- Finding: 0 suspicious users detected in current dataset.
-- ============================================================

WITH user_txns AS (
    SELECT
        user_id,
        txn_time,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_txn
    FROM transactions
),
dormant_gaps AS (
    SELECT
        user_id,
        txn_time AS reactivation_time,
        previous_txn,
        DATEDIFF(txn_time, previous_txn) AS gap_days
    FROM user_txns
    WHERE previous_txn IS NOT NULL
      AND DATEDIFF(txn_time, previous_txn) >= 90
)
SELECT
    d.user_id,
    d.gap_days,
    d.reactivation_time,
    COUNT(t.txn_id) AS post_gap_txns
FROM dormant_gaps d
JOIN transactions t
    ON t.user_id = d.user_id
   AND t.txn_time >= d.reactivation_time
GROUP BY
    d.user_id,
    d.gap_days,
    d.reactivation_time
HAVING COUNT(t.txn_id) >= 15
ORDER BY d.gap_days DESC;


-- ============================================================
-- P11: Velocity Spike
-- Rule: Peak monthly transaction count is at least 5x the
--       average monthly transaction count and peak >= 20.
-- Finding: 0 suspicious users detected in current dataset.
-- ============================================================

WITH monthly_counts AS (
    SELECT
        user_id,
        DATE_FORMAT(txn_time, '%Y-%m') AS month,
        COUNT(*) AS monthly_txns
    FROM transactions
    GROUP BY user_id, DATE_FORMAT(txn_time, '%Y-%m')
),
user_stats AS (
    SELECT
        user_id,
        MAX(monthly_txns) AS peak_monthly_txns,
        AVG(monthly_txns) AS avg_monthly_txns
    FROM monthly_counts
    GROUP BY user_id
)
SELECT
    user_id,
    peak_monthly_txns,
    ROUND(avg_monthly_txns, 2) AS avg_monthly_txns,
    ROUND(peak_monthly_txns / avg_monthly_txns, 2) AS spike_ratio
FROM user_stats
WHERE peak_monthly_txns >= 20
  AND peak_monthly_txns >= 5 * avg_monthly_txns
ORDER BY spike_ratio DESC;


-- ============================================================
-- P12: Geographic Impossibility
-- Rule: Consecutive transactions occur in different cities
--       within 60 minutes.
-- Finding: 15 suspicious users detected.
-- ============================================================

WITH ordered AS (
    SELECT
        user_id,
        txn_time,
        city,
        LAG(txn_time) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_time,
        LAG(city) OVER (
            PARTITION BY user_id
            ORDER BY txn_time
        ) AS previous_city
    FROM transactions
)
SELECT
    user_id,
    previous_city,
    city,
    previous_time,
    txn_time,
    TIMESTAMPDIFF(MINUTE, previous_time, txn_time) AS gap_minutes
FROM ordered
WHERE previous_city IS NOT NULL
  AND city <> previous_city
  AND TIMESTAMPDIFF(MINUTE, previous_time, txn_time) <= 60
ORDER BY gap_minutes;