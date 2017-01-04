/*
Navicat MySQL Data Transfer

Source Server         : 127.0.0.1
Source Server Version : 50711
Source Host           : localhost:3306
Source Database       : shcifco

Target Server Type    : MYSQL
Target Server Version : 50711
File Encoding         : 65001

Date: 2017-01-04 13:01:42
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for login_record
-- ----------------------------
DROP TABLE IF EXISTS `login_record`;
CREATE TABLE `login_record` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `client` varchar(20) NOT NULL,
  `login_at` datetime NOT NULL,
  `logout_at` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_login_at` (`login_at`),
  KEY `idx_username` (`username`)
) ENGINE=InnoDB AUTO_INCREMENT=23 DEFAULT CHARSET=utf8;
