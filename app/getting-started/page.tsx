import AppShell from "@/components/AppShell";
import GettingStartedChecklist from "@/components/GettingStartedChecklist";

export const dynamic = "force-dynamic";

export default function GettingStartedPage() {
  return (
    <AppShell title="Getting started">
      <main className="flex-1 px-6 py-10">
        <div className="mx-auto max-w-4xl animate-fade-in-up">
          <GettingStartedChecklist />
        </div>
      </main>
    </AppShell>
  );
}
