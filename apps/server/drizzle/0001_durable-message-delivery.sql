ALTER TABLE "offline_messages" ADD COLUMN "message_id" varchar(255) NOT NULL;--> statement-breakpoint
ALTER TABLE "offline_messages" ADD COLUMN "conversation_id" varchar(255) NOT NULL;--> statement-breakpoint
ALTER TABLE "offline_messages" ADD COLUMN "sender_device_id" varchar(255) NOT NULL;--> statement-breakpoint
ALTER TABLE "offline_messages" ADD COLUMN "recipient_device_id" varchar(255) NOT NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "offline_messages_message_id_idx" ON "offline_messages" USING btree ("message_id");--> statement-breakpoint
CREATE INDEX "offline_messages_recipient_created_at_idx" ON "offline_messages" USING btree ("recipient_id","created_at");