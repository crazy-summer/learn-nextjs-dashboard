import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcryptjs from 'bcryptjs';
import postgres from 'postgres';


const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
    try {
        const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
        return user[0];
    } catch (error) {
        console.error('Failed to fetch user:', error);
        throw new Error('Failed to fetch user.');
    }
}
export const { auth, signIn, signOut } = NextAuth({
    ...authConfig,
    providers: [
        Credentials({
            async authorize(credentials) {
                const parsedCredentials = z
                    .object({ email: z.string().email(), password: z.string().min(6) })
                    .safeParse(credentials);

                if (parsedCredentials.success) {
                    const { email, password } = parsedCredentials.data;
                    const user = await getUser(email);
                    if (!user) return null;
                    const passwordsMatch = await bcryptjs.compare(password, user.password);
                    if (passwordsMatch) return user;
                }
                console.log('Invalid credentials');
                return null;
            },
        }),
    ],
});

// middleware.ts auth.conig.ts auth.ts
// 三者的协作流程
// 用户访问页面
//
// 中间件 (middleware.ts) 拦截请求，调用 authConfig 的 authorized 逻辑。
//
// 权限检查
//
// 未登录用户访问 /dashboard → 跳转到 /login
//
// 已登录用户访问非仪表盘 → 重定向到 /dashboard
//
// 登录验证
//
// 用户在登录页提交表单 → auth.ts 中的 Credentials 提供者校验数据库信息。
//
// 会话管理
//
// 通过 auth 获取用户状态，signIn/signOut 控制会话。

// 举例场景
// 用户状态	访问路径	行为
// 未登录	/dashboard	跳转到 /login
// 未登录	/login	允许显示登录页
// 已登录	/dashboard	允许访问仪表盘
// 已登录	/login	强制重定向到 /dashboard
// 已登录	/about	强制重定向到 /dashboard