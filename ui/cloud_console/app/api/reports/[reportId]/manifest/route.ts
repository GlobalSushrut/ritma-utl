import { NextRequest, NextResponse } from "next/server";

const RITMA_CLOUD_URL =
  process.env.NEXT_PUBLIC_RITMA_CLOUD_URL ?? "http://localhost:8088";

export async function GET(
  _req: NextRequest,
  { params }: { params: { reportId: string } },
) {
  const { reportId } = params;

  const res = await fetch(
    `${RITMA_CLOUD_URL}/reports/${encodeURIComponent(reportId)}/manifest`,
  );

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return NextResponse.json(
      { error: text || res.statusText || "ritma_cloud /reports manifest failed" },
      { status: 500 },
    );
  }

  const body = await res.text();

  return new NextResponse(body, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="ritma-report-${reportId}.json"`,
    },
  });
}
