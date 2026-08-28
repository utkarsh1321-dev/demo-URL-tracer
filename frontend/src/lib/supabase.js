// src/lib/supabase.js
// Supabase client — initialized with PUBLIC env vars only.
// The service-role key NEVER appears here.

import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL      = import.meta.env.VITE_SUPABASE_URL;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
  console.error(
    '[URL Tracer] Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY in .env.local'
  );
}

export const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,          // store session in localStorage
    autoRefreshToken: true,        // auto-renew JWT before expiry
    detectSessionInUrl: true,      // handle magic-link / OAuth callbacks
  },
});
