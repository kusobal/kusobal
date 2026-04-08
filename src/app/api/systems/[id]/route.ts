import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import dbConnect from '@/lib/mongodb';
import System from '@/models/System';
import Customer from '@/models/Customer';

export async function PUT(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ id: string }> }
) {
  try {
    const params = await paramsPromise;
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const { name, category, subCategory, model, bios, idrac } = await request.json();

    if (!name || !category || !subCategory || !model || !bios || !idrac) {
      return NextResponse.json({ error: 'Missing fields' }, { status: 400 });
    }

    await dbConnect();

    // Get system and verify ownership
    const system = await System.findById(params.id);
    if (!system) {
      return NextResponse.json({ error: 'System not found' }, { status: 404 });
    }

    // Check if customer belongs to user
    const customer = await Customer.findOne({ _id: system.customer, user: session.user.id });
    if (!customer) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    system.name = name;
    system.category = category;
    system.subCategory = subCategory;
    system.model = model;
    system.bios = bios;
    system.idrac = idrac;
    system.updatedAt = new Date();

    await system.save();

    return NextResponse.json(system, { status: 200 });
  } catch (error) {
    console.error('Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}

export async function DELETE(
  request: NextRequest,
  { params: paramsPromise }: { params: Promise<{ id: string }> }
) {
  try {
    const params = await paramsPromise;
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await dbConnect();

    // Get system and verify ownership
    const system = await System.findById(params.id);
    if (!system) {
      return NextResponse.json({ error: 'System not found' }, { status: 404 });
    }

    // Check if customer belongs to user
    const customer = await Customer.findOne({ _id: system.customer, user: session.user.id });
    if (!customer) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await System.findByIdAndDelete(params.id);

    return NextResponse.json({ message: 'System deleted' }, { status: 200 });
  } catch (error) {
    console.error('Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
