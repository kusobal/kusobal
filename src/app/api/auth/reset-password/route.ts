import { NextRequest, NextResponse } from 'next/server';
import dbConnect from '@/lib/mongodb';
import User from '@/models/User';
import bcryptjs from 'bcryptjs';
import crypto from 'crypto';

export async function POST(request: NextRequest) {
  try {
    const { token, newPassword } = await request.json();

    if (!token || !newPassword) {
      return NextResponse.json(
        { error: 'Token and new password required' },
        { status: 400 }
      );
    }

    if (newPassword.length < 6) {
      return NextResponse.json(
        { error: 'Password must be at least 6 characters' },
        { status: 400 }
      );
    }

    await dbConnect();

    // Token'ı hash'le ve kontrol et
    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
    const now = new Date();

    console.log('DEBUG - Token validation:');
    console.log('- Incoming token:', token);
    console.log('- Hashed token:', hashedToken);
    console.log('- Current time:', now);

    const user = await User.findOne({
      resetToken: hashedToken,
      resetTokenExpiry: { $gt: now },
    });

    console.log('- User found:', user ? user.email : 'NOT FOUND');
    if (user) {
      console.log('- User resetTokenExpiry:', user.resetTokenExpiry);
      console.log('- Is expiry in future?', user.resetTokenExpiry > now);
    }

    if (!user) {
      return NextResponse.json(
        { error: 'Invalid or expired reset token' },
        { status: 400 }
      );
    }

    // Şifreyi hash'le ve kaydet
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(newPassword, salt);

    user.password = hashedPassword;
    user.resetToken = null;
    user.resetTokenExpiry = null;
    await user.save();

    return NextResponse.json(
      { message: 'Password reset successfully' },
      { status: 200 }
    );
  } catch (error) {
    console.error('Error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
