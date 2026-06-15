import type { Metadata } from "next";
import type { ReactNode } from "react";

import { AuthSessionProvider } from "@/components/session-provider";
import { Footer } from "@/components/footer";
import { Header } from "@/components/header";

import "./globals.css";

export const metadata: Metadata = {
  title: "Minister",
  description: "Identity platform — verifiable credential badges, your wallet, your terms.",
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
