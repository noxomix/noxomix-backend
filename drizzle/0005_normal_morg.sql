CREATE TABLE `subdomains` (
	`id` int AUTO_INCREMENT NOT NULL,
	`domain_id` int NOT NULL,
	`content` varchar(255) NOT NULL,
	`ipv4` varchar(45),
	`ipv6` varchar(45),
	`ipv4_record_id` int,
	`ipv6_record_id` int,
	`enabled` boolean NOT NULL DEFAULT true,
	`created_at` timestamp DEFAULT (now()),
	`updated_at` timestamp DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `subdomains_id` PRIMARY KEY(`id`),
	CONSTRAINT `subdomains_content_unique` UNIQUE(`content`)
);
--> statement-breakpoint
ALTER TABLE `subdomains` ADD CONSTRAINT `subdomains_domain_id_domains_id_fk` FOREIGN KEY (`domain_id`) REFERENCES `domains`(`id`) ON DELETE no action ON UPDATE no action;