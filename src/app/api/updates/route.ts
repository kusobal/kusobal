import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import dbConnect from '@/lib/mongodb';
import Update from '@/models/Update';

export async function GET(request: NextRequest) {
  try {
    await dbConnect();

    const { searchParams } = new URL(request.url);
    const productType = searchParams.get('productType');
    const vendor = searchParams.get('vendor');
    const sortBy = searchParams.get('sortBy') || 'releaseDate'; // releaseDate, severity, productType
    const limit = parseInt(searchParams.get('limit') || '100', 10);

    let filter: any = {};
    if (productType) filter.productType = productType;
    if (vendor) filter.vendor = vendor;

    const updates = await Update.find(filter)
      .sort({ [sortBy]: -1 })
      .limit(limit)
      .exec();

    return NextResponse.json(updates);
  } catch (error) {
    console.error('Error fetching updates:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    await dbConnect();

    const {
      productType,
      vendor,
      version,
      patch,
      releaseDate,
      category,
      releaseNotesEN,
      releaseNotesTR,
      url,
      severity,
    } = await request.json();

    if (!productType || !vendor || !version || !patch || !releaseDate || !releaseNotesEN || !releaseNotesTR) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    const newUpdate = await Update.create({
      productType,
      vendor,
      version,
      patch,
      releaseDate: new Date(releaseDate),
      category: category || 'Bug Fix',
      releaseNotesEN,
      releaseNotesTR,
      url: url || '',
      severity: severity || 'Medium',
    });

    return NextResponse.json(newUpdate, { status: 201 });
  } catch (error) {
    console.error('Error creating update:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
