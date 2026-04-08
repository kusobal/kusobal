import mongoose from 'mongoose';
import { sampleUpdates } from './seedUpdates';

const MONGODB_URI = process.env.MONGODB_URI!;

if (!MONGODB_URI) {
  throw new Error('Please define the MONGODB_URI environment variable inside .env.local');
}

let cached = (global as any).mongoose;

if (!cached) {
  cached = (global as any).mongoose = { conn: null, promise: null, seeded: false };
}

async function dbConnect() {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const opts = {
      bufferCommands: false,
    };

    cached.promise = mongoose.connect(MONGODB_URI, opts).then((mongoose) => {
      return mongoose;
    });
  }

  try {
    cached.conn = await cached.promise;
    
    // Development'ta her bağlantıda seed'le (eski veriler silinip yeni eklenir)
    if (process.env.NODE_ENV === 'development') {
      await seedDatabaseOnce();
    }
  } catch (e) {
    cached.promise = null;
    throw e;
  }

  return cached.conn;
}

async function seedDatabaseOnce() {
  try {
    const Update = mongoose.models.Update || mongoose.model('Update');
    
    // Eski veriyi sil
    await Update.deleteMany({});
    console.log('📊 Cleared old updates');
    
    console.log('📊 Seeding database with sample updates...');
      
      await Update.insertMany(sampleUpdates);
      console.log(`✅ Successfully seeded ${sampleUpdates.length} updates`);
  } catch (error) {
    console.error('❌ Error seeding database:', error);
  }
}

export default dbConnect;