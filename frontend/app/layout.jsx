import "./globals.css";

export const metadata = {
  title: "Threat Intel",
  description: "AI-powered IOC analysis",
};

export default function RootLayout({ children }) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
