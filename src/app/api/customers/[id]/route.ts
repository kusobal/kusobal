import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import dbConnect from '@/lib/mongodb';
import Customer from '@/models/Customer';

export async function GET(request: NextRequest, { params: paramsPromise }: { params: Promise<{ id: string }> }) {
  try {
    const params = await paramsPromise;
    const session = await getServerSession(authOptions);
    console.log('Session in customer detail:', session);
    console.log('Customer ID:', params.id);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    await dbConnect();

    const customer = await Customer.findOne({ _id: params.id, user: session.user.id });
    console.log('Customer found:', customer);
    if (!customer) {
      return NextResponse.json({ error: 'Customer not found' }, { status: 404 });
    }

    return NextResponse.json(customer);
  } catch (error) {
    console.error('Customer Detail Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}