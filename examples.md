# Test prompts

## 1. Basic

Analyze this PostgreSQL query:

SELECT * FROM orders
WHERE user_id = 12345
ORDER BY created_at DESC
LIMIT 20;

## 2. Leading wildcard

Analyze:

SELECT id, email
FROM users
WHERE email LIKE '%gmail.com';

## 3. EXPLAIN

Analyze this PostgreSQL query and EXPLAIN:

SELECT *
FROM orders
WHERE user_id = 12345
ORDER BY created_at DESC
LIMIT 20;

EXPLAIN output:
Seq Scan on orders  (cost=0.00..25000.00 rows=500000 width=120)
  Filter: (user_id = 12345)
  Rows Removed by Filter: 499900
