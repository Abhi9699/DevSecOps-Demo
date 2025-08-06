
import { NextRequest, NextResponse } from 'next/server';
import { GoogleGenerativeAI } from '@google/generative-ai';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');
console.log('GEMINI_API_KEY loaded:', !!process.env.GEMINI_API_KEY); // Log to check if key is loaded

export async function POST(req: NextRequest) {
  try {
            const { message } = await req.json();

    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash'});
    const chat = model.startChat({
      history: [
        {
          role: "user",
          parts: [{ text: "Hello, I have 2 dogs in my house." }],
        },
        {
          role: "model",
          parts: [{ text: "Great to meet you. What would you like to know?" }],
        },
      ],
      generationConfig: {
        maxOutputTokens: 100,
      },
    });

    const result = await chat.sendMessage(message);
    const text = result.response.text();

    return NextResponse.json({ reply: text });
  } catch (error) {
    console.error('Error processing chat message:', error);
    return NextResponse.json({ error: 'Internal Server Error' }, { status: 500 });
  }
}
