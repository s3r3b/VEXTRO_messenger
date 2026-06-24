import { pgTable, varchar, text, timestamp, uuid } from 'drizzle-orm/pg-core';

export const offlineMessages = pgTable('offline_messages', {
    id: uuid('id').defaultRandom().primaryKey(),
    recipientId: varchar('recipient_id', { length: 255 }).notNull(),
    senderId: varchar('sender_id', { length: 255 }).notNull(),
    // Ślepy serwer nie wie co tu jest. To po prostu blob Base64.
    ciphertext: text('ciphertext').notNull(),
    createdAt: timestamp('created_at').defaultNow().notNull(),
});