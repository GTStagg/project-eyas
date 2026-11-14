import { PLAYBOOKS } from "@/lib/ngsiem-playbooks";
import NgsiemClient from "./NgsiemClient";

// The page only lists and filters playbooks; the query itself is looked up on
// the server by id when one is run. Dropping `cql` here keeps the 85 KB of
// queries out of what the browser downloads.
export default function NgsiemPage() {
  const playbooks = PLAYBOOKS.map(({ cql: _cql, ...summary }) => summary);
  return <NgsiemClient playbooks={playbooks} />;
}
