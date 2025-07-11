CREATE TABLE `servers` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`name` text NOT NULL,
	`subdomain` text NOT NULL,
	`status` text DEFAULT 'stopped' NOT NULL,
	`ram` integer NOT NULL,
	`storage` integer NOT NULL,
	`cpu_cores` integer NOT NULL,
	`host` text NOT NULL,
	`server_version` text NOT NULL,
	`minecraft_version` text NOT NULL,
	`user_id` integer NOT NULL,
	`created_at` integer,
	`updated_at` integer,
	`deleted_at` integer,
	`stopped_at` integer,
	`last_active_at` integer,
	FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE UNIQUE INDEX `servers_subdomain_unique` ON `servers` (`subdomain`);