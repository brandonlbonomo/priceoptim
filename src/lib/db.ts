import Database from "better-sqlite3";
import path from "path";

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (db) return db;

  const dbPath = process.env.DATABASE_PATH || "./data/subscribers.db";
  const dir = path.dirname(dbPath);

  // Ensure directory exists
  const fs = require("fs");
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  db = new Database(dbPath);
  db.pragma("journal_mode = WAL");

  // Create table if it doesn't exist
  db.exec(`
    CREATE TABLE IF NOT EXISTS subscribers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      first_name TEXT,
      source TEXT NOT NULL DEFAULT 'unknown',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);

  return db;
}

export function addSubscriber(
  email: string,
  source: string,
  firstName?: string,
): { success: boolean; message: string } {
  const database = getDb();

  try {
    const stmt = database.prepare(
      "INSERT INTO subscribers (email, source, first_name) VALUES (?, ?, ?)",
    );
    stmt.run(email.toLowerCase().trim(), source, firstName || null);
    return { success: true, message: "You're on the list! Watch your inbox for exclusive deals." };
  } catch (error: unknown) {
    if (error instanceof Error && error.message.includes("UNIQUE constraint failed")) {
      return { success: true, message: "You're already subscribed! We'll keep the deals coming." };
    }
    throw error;
  }
}

export function getSubscribers(): Array<{
  id: number;
  email: string;
  first_name: string | null;
  source: string;
  created_at: string;
}> {
  const database = getDb();
  const stmt = database.prepare("SELECT * FROM subscribers ORDER BY created_at DESC");
  return stmt.all() as Array<{
    id: number;
    email: string;
    first_name: string | null;
    source: string;
    created_at: string;
  }>;
}
