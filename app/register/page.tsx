import { redirect } from "next/navigation";
import { isRegistered, MIN_PASSWORD_LENGTH } from "@/lib/auth/store";
import { getConfigStatus } from "@/lib/config/runtime";
import { getDeploymentPolicy } from "@/lib/config/deployment-policy";
import ClassificationBanner from "@/components/ClassificationBanner";
import { RegisterForm } from "./form";

export const dynamic = "force-dynamic";

export default async function RegisterPage() {
  if (await isRegistered()) {
    redirect("/login");
  }
  const status = getConfigStatus();
  const policy = getDeploymentPolicy();
  return (
    <main className="relative z-10 mx-auto flex min-h-screen w-full max-w-2xl flex-col justify-center px-6 py-16">
      <ClassificationBanner />
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight">Set up access</h1>
        <p className="mt-2 text-sm text-neutral-400">
          First-run setup for Eyas. Pick a console password, then connect to Anthropic and CrowdStrike Falcon. Credentials are saved on this device only — never sent to the browser.
        </p>
      </header>
      <RegisterForm
        minLength={MIN_PASSWORD_LENGTH}
        status={status}
        gatewayOnly={policy.gatewayOnly}
        forcedGatewayUrl={policy.forcedGatewayUrl}
      />
    </main>
  );
}
