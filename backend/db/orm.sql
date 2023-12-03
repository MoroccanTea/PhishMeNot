-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1
-- Generation Time: Dec 01, 2023 at 04:10 PM
-- Server version: 10.4.28-MariaDB
-- PHP Version: 8.2.4

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `orm`
--

-- --------------------------------------------------------

--
-- Table structure for table `emailscans`
--

CREATE TABLE `emailscans` (
  `EmailScanID` int(11) NOT NULL,
  `UserID` int(11) NOT NULL,
  `LastScanDate` date NOT NULL,
  `IsSecure` tinyint(1) NOT NULL,
  `IsSuspiciousEmailAddress` tinyint(1) NOT NULL,
  `SenderAddress` varchar(255) DEFAULT NULL,
  `IsSenderBlacklisted` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `scans`
--

CREATE TABLE `scans` (
  `ScanID` int(11) NOT NULL,
  `WebsiteID` int(11) NOT NULL,
  `ScanDate` date NOT NULL,
  `PhishingScore` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `UserID` int(11) NOT NULL,
  `Username` varchar(255) NOT NULL,
  `Password` varchar(255) NOT NULL,
  `IsGoogleAccount` tinyint(1) NOT NULL,
  `GoogleToken` varchar(255) DEFAULT NULL,
  `Email` varchar(255) DEFAULT NULL,
  `VirusTotalAPIKey` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `websites`
--

CREATE TABLE `websites` (
  `WebsiteID` int(11) NOT NULL,
  `URL` varchar(255) NOT NULL,
  `LastScannedDate` date NOT NULL,
  `IsSecure` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Table structure for table `websitestatistics`
--

CREATE TABLE `websitestatistics` (
  `StatisticID` int(11) NOT NULL,
  `WebsiteID` int(11) NOT NULL,
  `VisitDate` date NOT NULL,
  `IsSafe` tinyint(1) NOT NULL,
  `IsMalicious` tinyint(1) NOT NULL,
  `IsBlacklisted` tinyint(1) NOT NULL,
  `IsWhitelisted` tinyint(1) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

--
-- Indexes for dumped tables
--

--
-- Indexes for table `emailscans`
--
ALTER TABLE `emailscans`
  ADD PRIMARY KEY (`EmailScanID`),
  ADD KEY `UserID` (`UserID`);

--
-- Indexes for table `scans`
--
ALTER TABLE `scans`
  ADD PRIMARY KEY (`ScanID`),
  ADD KEY `WebsiteID` (`WebsiteID`);

--
-- Indexes for table `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`UserID`);

--
-- Indexes for table `websites`
--
ALTER TABLE `websites`
  ADD PRIMARY KEY (`WebsiteID`);

--
-- Indexes for table `websitestatistics`
--
ALTER TABLE `websitestatistics`
  ADD PRIMARY KEY (`StatisticID`),
  ADD KEY `WebsiteID` (`WebsiteID`);

--
-- AUTO_INCREMENT for dumped tables
--

--
-- AUTO_INCREMENT for table `emailscans`
--
ALTER TABLE `emailscans`
  MODIFY `EmailScanID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `scans`
--
ALTER TABLE `scans`
  MODIFY `ScanID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `users`
--
ALTER TABLE `users`
  MODIFY `UserID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `websites`
--
ALTER TABLE `websites`
  MODIFY `WebsiteID` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT for table `websitestatistics`
--
ALTER TABLE `websitestatistics`
  MODIFY `StatisticID` int(11) NOT NULL AUTO_INCREMENT;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `emailscans`
--
ALTER TABLE `emailscans`
  ADD CONSTRAINT `emailscans_ibfk_1` FOREIGN KEY (`UserID`) REFERENCES `users` (`UserID`);

--
-- Constraints for table `scans`
--
ALTER TABLE `scans`
  ADD CONSTRAINT `scans_ibfk_1` FOREIGN KEY (`WebsiteID`) REFERENCES `websites` (`WebsiteID`);

--
-- Constraints for table `websitestatistics`
--
ALTER TABLE `websitestatistics`
  ADD CONSTRAINT `websitestatistics_ibfk_1` FOREIGN KEY (`WebsiteID`) REFERENCES `websites` (`WebsiteID`);
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
