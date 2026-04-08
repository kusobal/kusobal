import { NextRequest, NextResponse } from 'next/server';
import dbConnect from '@/lib/mongodb';
import User from '@/models/User';
import crypto from 'crypto';

export async function POST(request: NextRequest) {
  try {
    const { email } = await request.json();

    if (!email) {
      return NextResponse.json({ error: 'Email required' }, { status: 400 });
    }

    await dbConnect();
    const user = await User.findOne({ email });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Generate reset token
    const resetToken = crypto.randomBytes(32).toString('hex');
    const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiryTime = new Date(Date.now() + 10 * 60 * 1000); // 10 dakika

    console.log('DEBUG - Token generation:');
    console.log('- Plain token:', resetToken);
    console.log('- Hashed token:', hashedToken);
    console.log('- Expiry time:', expiryTime);

    user.resetToken = hashedToken;
    user.resetTokenExpiry = expiryTime;
    const savedUser = await user.save();

    console.log('DEBUG - User saved with reset token');
    console.log('- resetToken:', savedUser.resetToken);
    console.log('- resetTokenExpiry:', savedUser.resetTokenExpiry);

    // Reset linki
    const resetUrl = `${process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'}/auth/reset-password/${resetToken}`;

    // Development'da linki console'a yaz
    if (process.env.NODE_ENV === 'development') {
      console.log('='.repeat(60));
      console.log('PASSWORD RESET EMAIL');
      console.log('='.repeat(60));
      console.log(`To: ${email}`);
      console.log(`Reset Link: ${resetUrl}`);
      console.log('Valid for 10 minutes');
      console.log('='.repeat(60));
      
      return NextResponse.json(
        { 
          message: 'Password reset link generated (check console)',
          resetUrl: resetUrl // Development'da frontend'e de gönder
        },
        { status: 200 }
      );
    }

    // Production'da email gönder
    try {
      // Gerçek email implementasyonu buraya gelecek
      // Şimdilik skip
      return NextResponse.json(
        { message: 'Password reset email sent' },
        { status: 200 }
      );
    } catch (emailError) {
      console.error('Email send error:', emailError);
      return NextResponse.json(
        { error: 'Email could not be sent. Please try again.' },
        { status: 500 }
      );
    }
  } catch (error) {
    console.error('Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
