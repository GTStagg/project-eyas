import { redirect } from "next/navigation";
import { isRegistered } from "@/lib/auth/store";
import ClassificationBanner from "@/components/ClassificationBanner";
import { LoginForm } from "./form";

export const dynamic = "force-dynamic";

type SearchParams = Promise<{ next?: string; err?: string }>;

export default async function LoginPage({ searchParams }: { searchParams: SearchParams }) {
  if (!(await isRegistered())) {
    redirect("/register");
  }
  const params = await searchParams;
  const configError = params.err === "config";
  return (
    <main className="relative z-10 mx-auto flex min-h-screen w-full max-w-md flex-col justify-center px-6 py-16">
      <ClassificationBanner />
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
      </header>
      {configError ? (
        <p className="mb-4 rounded-md border border-red-900 bg-red-950/40 px-3 py-2 text-sm text-oxblood-300">
          Server is missing <span className="font-mono">AUTH_SESSION_SECRET</span>. Set it in the environment and restart.
        </p>
      ) : null}
      <LoginForm next={params.next ?? "/home"} />
    </main>
  );
}
