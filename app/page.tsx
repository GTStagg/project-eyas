import Chat from "@/components/Chat";
import PostRegisterBanner from "@/components/PostRegisterBanner";

export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ postRegister?: string }>;
}) {
  const sp = await searchParams;
  const showRestart = sp.postRegister === "restart-extras";
  return (
    <>
      {showRestart ? <PostRegisterBanner kind="restart-extras" /> : null}
      <Chat />
    </>
  );
}
