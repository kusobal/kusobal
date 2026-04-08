import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import dbConnect from '@/lib/mongodb';
import Update from '@/models/Update';

export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    await dbConnect();
    const update = await Update.findById(id);

    if (!update) {
      return NextResponse.json({ error: 'Update not found' }, { status: 404 });
    }

    return NextResponse.json(update);
  } catch (error) {
    console.error('Error fetching update:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function PUT(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Admin check
    const user = session.user as any;
    if (user.email !== process.env.ADMIN_EMAIL) {
      return NextResponse.json({ error: 'Admin access required' }, { status: 403 });
    }

    await dbConnect();
    const update = await Update.findById(id);

    if (!update) {
      return NextResponse.json({ error: 'Update not found' }, { status: 404 });
    }

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

    if (productType) update.productType = productType;
    if (vendor) update.vendor = vendor;
    if (version) update.version = version;
    if (patch) update.patch = patch;
    if (releaseDate) update.releaseDate = new Date(releaseDate);
    if (category) update.category = category;
    if (releaseNotesEN) update.releaseNotesEN = releaseNotesEN;
    if (releaseNotesTR) update.releaseNotesTR = releaseNotesTR;
    if (url) update.url = url;
    if (severity) update.severity = severity;

    update.updatedAt = new Date();
    await update.save();

    return NextResponse.json(update);
  } catch (error) {
    console.error('Error updating update:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    // Admin check
    const user = session.user as any;
    if (user.email !== process.env.ADMIN_EMAIL) {
      return NextResponse.json({ error: 'Admin access required' }, { status: 403 });
    }

    await dbConnect();
    const update = await Update.findByIdAndDelete(id);

    if (!update) {
      return NextResponse.json({ error: 'Update not found' }, { status: 404 });
    }

    return NextResponse.json({ message: 'Update deleted successfully' });
  } catch (error) {
    console.error('Error deleting update:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
