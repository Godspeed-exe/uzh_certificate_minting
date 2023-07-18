CREATE TABLE uzh_certificate.students (
	id INT auto_increment NULL,
	first_name varchar(255) NULL,
	last_name varchar(255) NULL,
	cardano_address varchar(255) NOT NULL,
	cardano_testnet varchar(255) NOT NULL,
	identity_hash varchar(64) NULL,
	status INT DEFAULT 0 NULL,
	CONSTRAINT students_PK PRIMARY KEY (id)
)
ENGINE=InnoDB
DEFAULT CHARSET=utf8mb4
COLLATE=utf8mb4_0900_ai_ci;
