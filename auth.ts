import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';

import type { User } from '@/app/lib/definitions';
import {getGeneralApiProblem} from "@/app/lib/api/api-problem";

export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [Credentials({
        async authorize(credentials) {
            const parsedCredentials = z
                .object({ email: z.string().email(), password: z.string().min(6) })
                .safeParse(credentials);

            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                console.log(JSON.stringify({ username:email, password:password }));
                const response = await fetch('http://127.0.0.1:5328/api/v1/auth/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username:email, password:password }),
                });
                console.log(response);
                if (!response.ok) {
                    const problem = getGeneralApiProblem(response);
                    console.log(problem);
                    if (problem) return null;
                }

                try {
                    const data = response.body;
                    return { kind: "ok", token: data?.auth_token, user: data?.user };
                } catch {
                    return { kind: "bad-data" };
                }
            }
            return null;
        },
    }),],
});