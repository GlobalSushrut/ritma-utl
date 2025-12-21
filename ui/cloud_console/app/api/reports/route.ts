import { NextRequest, NextResponse } from "next/server";

const RITMA_CLOUD_URL =
  process.env.NEXT_PUBLIC_RITMA_CLOUD_URL ?? "http://localhost:8088";

export async function POST(req: NextRequest) {
  const body = (await req.json()) as {
    org_id: string;
    tenant_id?: string | null;
    scope: string;
    framework?: string | null;
  };

  const res = await fetch(`${RITMA_CLOUD_URL}/reports`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      org_id: body.org_id,
      tenant_id: body.tenant_id ?? null,
      scope: body.scope,
      framework: body.framework ?? null,
    }),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return NextResponse.json(
      { error: text || res.statusText || "ritma_cloud /reports failed" },
      { status: 500 },
    );
  }

  const json = await res.json();
  return NextResponse.json(json);
}
