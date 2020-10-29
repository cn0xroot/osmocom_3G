--modelled roughly after TS 23.008 version 13.3.0

CREATE TABLE subscriber (
	id		INTEGER PRIMARY KEY,
	-- Chapter 2.1.1.1
	imsi		VARCHAR(15) UNIQUE NOT NULL,
	-- Chapter 2.1.2
	msisdn		VARCHAR(15) UNIQUE,
	-- Chapter 2.2.3: Most recent / current IMEI
	imeisv		VARCHAR,
	-- Chapter 2.4.5
	vlr_number	VARCHAR(15),
	-- Chapter 2.4.6
	hlr_number	VARCHAR(15),
	-- Chapter 2.4.8.1
	sgsn_number	VARCHAR(15),
	-- Chapter 2.13.10
	sgsn_address	VARCHAR,
	-- Chapter 2.4.8.2
	ggsn_number	VARCHAR(15),
	-- Chapter 2.4.9.2
	gmlc_number	VARCHAR(15),
	-- Chapter 2.4.23
	smsc_number	VARCHAR(15),
	-- Chapter 2.4.24
	periodic_lu_tmr	INTEGER,
	-- Chapter 2.13.115
	periodic_rau_tau_tmr INTEGER,
	-- Chapter 2.1.1.2: network access mode
	nam_cs		BOOLEAN NOT NULL DEFAULT 1,
	nam_ps		BOOLEAN NOT NULL DEFAULT 1,
	-- Chapter 2.1.8
	lmsi		INTEGER,

	-- The below purged flags might not even be stored non-volatile,
	-- refer to TS 23.012 Chapter 3.6.1.4
	-- Chapter 2.7.5
	ms_purged_cs	BOOLEAN NOT NULL DEFAULT 0,
	-- Chapter 2.7.6
	ms_purged_ps	BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE subscriber_apn (
	subscriber_id	INTEGER,		-- subscriber.id
	apn		VARCHAR(256) NOT NULL
);

-- Chapter 2.1.3
CREATE TABLE subscriber_multi_msisdn (
	subscriber_id	INTEGER,		-- subscriber.id
	msisdn		VARCHAR(15) NOT NULL
);

CREATE TABLE auc_2g (
	subscriber_id	INTEGER PRIMARY KEY,	-- subscriber.id
	algo_id_2g	INTEGER NOT NULL,	-- enum osmo_auth_algo value
	ki		VARCHAR(32) NOT NULL	-- hex string: subscriber's secret key (128bit)
);

CREATE TABLE auc_3g (
	subscriber_id	INTEGER PRIMARY KEY,	-- subscriber.id
	algo_id_3g	INTEGER NOT NULL,	-- enum osmo_auth_algo value
	k		VARCHAR(32) NOT NULL,	-- hex string: subscriber's secret key (128bit)
	op		VARCHAR(32),		-- hex string: operator's secret key (128bit)
	opc		VARCHAR(32),		-- hex string: derived from OP and K (128bit)
	sqn		INTEGER NOT NULL DEFAULT 0,	-- sequence number of key usage
	ind_bitlen	INTEGER NOT NULL DEFAULT 5	-- nr of index bits at lower SQN end
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_subscr_imsi ON subscriber (imsi);
-- SELECT algo_id_2g, ki, algo_id_3g, k, op, opc, sqn FROM subscriber LEFT JOIN auc_2g ON auc_2g.subscriber_id = subscriber.id LEFT JOIN auc_3g ON auc_3g.subscriber_id = subscriber.id WHERE imsi = ?
