import type { Metadata } from "next";
import type { ReactNode } from "react";

import { AuthSessionProvider } from "@/components/session-provider";
import { Footer } from "@/components/footer";
import { Header } from "@/components/header";

import "./globals.css";

export const metadata: Metadata = {
  title: "Minister",
  description:
    "Badges for facts you've verified about yourself. You hold them, and you decide exactly who sees them.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body className="flex min-h-screen flex-col">
        <AuthSessionProvider>
          <Header />
          <main className="flex-1">{children}</main>
          <Footer />
        </AuthSessionProvider>
      </body>
    </html>
  );
}
