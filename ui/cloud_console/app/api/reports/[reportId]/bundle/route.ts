import { NextRequest, NextResponse } from "next/server";

const RITMA_CLOUD_URL =
  process.env.NEXT_PUBLIC_RITMA_CLOUD_URL ?? "http://localhost:8088";

export async function GET(
  _req: NextRequest,
  { params }: { params: { reportId: string } },
) {
  const { reportId } = params;

  // Fetch the manifest from ritma_cloud and transform it into a stub PDF-like document.
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

  const manifest = await res.json();
  const pretty = JSON.stringify(manifest, null, 2);

  const content =
    `Ritma Compliance Report (stub PDF)\n` +
    `Report ID: ${reportId}\n` +
    `Generated at: ${new Date().toISOString()}\n` +
    `\nManifest:\n${pretty}\n`;

  return new NextResponse(content, {
    status: 200,
    headers: {
      "content-type": "application/pdf; charset=utf-8",
      "content-disposition": `attachment; filename="ritma-report-${reportId}.pdf"`,
    },
  });
}
