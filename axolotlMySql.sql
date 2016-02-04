-- --------------------------------------------------------
-- Host:                         192.168.92.202
-- Server version:               5.5.25a - MySQL Community Server (GPL)
-- Server OS:                    Win64
-- HeidiSQL Version:             9.3.0.4984
-- --------------------------------------------------------

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET NAMES utf8mb4 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;

-- Dumping database structure for socialstore
CREATE DATABASE IF NOT EXISTS `axolotlstore` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci */;
USE `axolotlstore`;


-- Dumping structure for table socialstore.axolotl_identities
CREATE TABLE IF NOT EXISTS `axolotl_identities` (
  `id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `recipient_id` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `registration_id` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `public_key` blob,
  `private_key` blob,
  `next_prekey_id` int(11) DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `owner` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table socialstore.axolotl_identities: ~0 rows (approximately)
/*!40000 ALTER TABLE `axolotl_identities` DISABLE KEYS */;
/*!40000 ALTER TABLE `axolotl_identities` ENABLE KEYS */;


-- Dumping structure for table socialstore.axolotl_prekeys
CREATE TABLE IF NOT EXISTS `axolotl_prekeys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `prekey_id` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT '0',
  `sent_to_server` int(11) NOT NULL DEFAULT '0',
  `record` blob NOT NULL,
  `owner` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `prekey_id` (`prekey_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table socialstore.axolotl_prekeys: ~0 rows (approximately)
/*!40000 ALTER TABLE `axolotl_prekeys` DISABLE KEYS */;
/*!40000 ALTER TABLE `axolotl_prekeys` ENABLE KEYS */;


-- Dumping structure for table socialstore.axolotl_sender_keys
CREATE TABLE IF NOT EXISTS `axolotl_sender_keys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `sender_key_id` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `record` blob,
  `owner` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `sender_key_id` (`sender_key_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table socialstore.axolotl_sender_keys: ~0 rows (approximately)
/*!40000 ALTER TABLE `axolotl_sender_keys` DISABLE KEYS */;
/*!40000 ALTER TABLE `axolotl_sender_keys` ENABLE KEYS */;


-- Dumping structure for table socialstore.axolotl_sessions
CREATE TABLE IF NOT EXISTS `axolotl_sessions` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `recipient_id` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `device_id` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  `record` blob NOT NULL,
  `timestamp` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `owner` varchar(50) COLLATE utf8mb4_unicode_ci NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `recipient_id` (`recipient_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table socialstore.axolotl_sessions: ~0 rows (approximately)
/*!40000 ALTER TABLE `axolotl_sessions` DISABLE KEYS */;
/*!40000 ALTER TABLE `axolotl_sessions` ENABLE KEYS */;


-- Dumping structure for table socialstore.axolotl_signed_prekeys
CREATE TABLE IF NOT EXISTS `axolotl_signed_prekeys` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `prekey_id` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `timestamp` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `record` blob,
  `owner` varchar(50) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `prekey_id` (`prekey_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Dumping data for table socialstore.axolotl_signed_prekeys: ~0 rows (approximately)
/*!40000 ALTER TABLE `axolotl_signed_prekeys` DISABLE KEYS */;
/*!40000 ALTER TABLE `axolotl_signed_prekeys` ENABLE KEYS */;
/*!40101 SET SQL_MODE=IFNULL(@OLD_SQL_MODE, '') */;
/*!40014 SET FOREIGN_KEY_CHECKS=IF(@OLD_FOREIGN_KEY_CHECKS IS NULL, 1, @OLD_FOREIGN_KEY_CHECKS) */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
