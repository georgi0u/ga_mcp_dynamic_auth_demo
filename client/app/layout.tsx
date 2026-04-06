import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MCP Auth Demo",
  description: "A Next.js client for the MCP authorization demo backend.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}

