CREATE TABLE "identities" (
	"user_id" varchar(255) PRIMARY KEY NOT NULL,
	"identity_key" text NOT NULL,
	"signed_prekey" text NOT NULL,
	"signature" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL,
	"updated_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "offline_messages" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"recipient_id" varchar(255) NOT NULL,
	"sender_id" varchar(255) NOT NULL,
	"ciphertext" text NOT NULL,
	"created_at" timestamp DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "one_time_prekeys" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" varchar(255) NOT NULL,
	"key_id" integer NOT NULL,
	"key" text NOT NULL
);
--> statement-breakpoint
ALTER TABLE "one_time_prekeys" ADD CONSTRAINT "one_time_prekeys_user_id_identities_user_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."identities"("user_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "one_time_prekeys_user_key_id_idx" ON "one_time_prekeys" USING btree ("user_id","key_id");