
-- 2G only subscriber
INSERT INTO subscriber (id, imsi) VALUES (1, '901990000000001');
INSERT INTO auc_2g (subscriber_id, algo_id_2g, ki) VALUES (1, 1, '000102030405060708090a0b0c0d0e0f');

-- 3G only subscriber
INSERT INTO subscriber (id, imsi) VALUES (2, '901990000000002');
INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, opc, sqn) VALUES (2, 5, '000102030405060708090a0b0c0d0e0f', '101112131415161718191a1b1c1d1e1f', 0);

-- 2G + 3G subscriber
INSERT INTO subscriber (id, imsi) VALUES (3, '901990000000003');
INSERT INTO auc_2g (subscriber_id, algo_id_2g, ki) VALUES (3, 1, '000102030405060708090a0b0c0d0e0f');
INSERT INTO auc_3g (subscriber_id, algo_id_3g, k, opc, sqn) VALUES (3, 5, '000102030405060708090a0b0c0d0e0f', '101112131415161718191a1b1c1d1e1f', 0);
