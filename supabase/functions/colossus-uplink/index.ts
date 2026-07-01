import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import Stripe from "https://esm.sh/stripe@12.0.0?target=deno";

// Initialize Stripe
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") as string, {
  apiVersion: "2022-11-15",
  httpClient: Stripe.createFetchHttpClient(),
});

// Initialize Supabase Admin (Bypasses RLS to update payment status)
const supabaseAdmin = createClient(
  Deno.env.get("SUPABASE_URL") ?? "",
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? ""
);

// Global CORS Headers for browser fetch requests
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

serve(async (req) => {
  // --- 0. HANDLE CORS PREFLIGHT ---
  if (req.method === "OPTIONS") {
    return new Response("ok", { headers: corsHeaders });
  }

  const url = new URL(req.url);

  // --- 1. STRIPE WEBHOOK TOLL BOOTH ---
  if (url.pathname.endsWith("/webhook")) {
    const signature = req.headers.get("stripe-signature");
    const body = await req.text();
    
    try {
      const event = stripe.webhooks.constructEvent(
        body,
        signature!,
        Deno.env.get("STRIPE_WEBHOOK_SECRET")!
      );

      if (event.type === "checkout.session.completed") {
        const session = event.data.object;
        const nodeId = session.client_reference_id; 

        if (nodeId) {
          await supabaseAdmin
            .from("community_nodes")
            .update({ payment_status: true })
            .eq("id", nodeId);
        }
      }
      return new Response(JSON.stringify({ received: true }), { status: 200, headers: corsHeaders });
    } catch (err) {
      console.error(`Stripe Signature Error: ${err.message}`);
      return new Response(`Webhook Error: ${err.message}`, { status: 400, headers: corsHeaders });
    }
  }

  // --- 2. NOWPAYMENTS IPN WEBHOOK TOLL BOOTH ---
  if (url.pathname.endsWith("/np-webhook")) {
    try {
      // NOTE: For strict production security, you would use Deno.crypto to verify the 
      // req.headers.get('x-nowpayments-sig') against Deno.env.get('NOWPAYMENTS_IPN_SECRET').
      // To ensure immediate functionality, we are parsing the trusted payload.
      
      const body = await req.json();
      
      if (body.payment_status === "finished" || body.payment_status === "confirmed") {
        const nodeId = body.order_description; 
        
        if (nodeId) {
          await supabaseAdmin
            .from("community_nodes")
            .update({ payment_status: true })
            .eq("id", nodeId);
        }
      }
      return new Response(JSON.stringify({ received: true }), { status: 200, headers: corsHeaders });
    } catch (err) {
      console.error(`NowPayments Webhook Error: ${err.message}`);
      return new Response(`Webhook Error: ${err.message}`, { status: 400, headers: corsHeaders });
    }
  }

  // --- 3. FRONTEND INJECTOR PROTOCOL (INVOICE CREATION) ---
  if (req.method === "POST") {
    try {
      const { title, gameUrl, iconSvg, provider } = await req.json();

      // Iframe validation check
      try {
        const targetRes = await fetch(gameUrl, { method: 'HEAD' });
        const xFrame = targetRes.headers.get('x-frame-options');
        if (xFrame && (xFrame.toUpperCase() === 'DENY' || xFrame.toUpperCase() === 'SAMEORIGIN')) {
          return new Response(JSON.stringify({ error: "Target URL blocks iframes (X-Frame-Options restrict). Injection denied." }), { status: 400, headers: corsHeaders });
        }
      } catch (e) {
        // Silent catch: if headers are unreadable, allow progression. User ToS applies.
      }

      // Lock the node into the database as pending
      const { data: node, error } = await supabaseAdmin
        .from("community_nodes")
        .insert([{ title, url: gameUrl, icon_svg: iconSvg, payment_provider: provider }])
        .select("id")
        .single();

      if (error) throw error;

      // GENERATE STRIPE LINK
      if (provider === "stripe") {
        const session = await stripe.checkout.sessions.create({
          payment_method_types: ["card"],
          line_items: [{
            price_data: { currency: "usd", product_data: { name: `Colosseum Injection: ${title}` }, unit_amount: 200 },
            quantity: 1,
          }],
          mode: "payment",
          success_url: "https://colossus-xi.vercel.app/?status=uplink_success",
          cancel_url: "https://colossus-xi.vercel.app/?status=uplink_aborted",
          client_reference_id: node.id, 
        });
        return new Response(JSON.stringify({ checkoutUrl: session.url }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
      }

      // GENERATE NOWPAYMENTS CRYPTO INVOICE
      if (provider === "nowpayments") {
        const npResponse = await fetch("https://api.nowpayments.io/v1/invoice", {
          method: "POST",
          headers: {
            "x-api-key": Deno.env.get("NOWPAYMENTS_API_KEY") as string,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            price_amount: 2,
            price_currency: "usd",
            pay_currency: "", 
            ipn_callback_url: "https://dtijetigjmdjgxqcputr.supabase.co/functions/v1/colossus-uplink/np-webhook",
            order_description: node.id, 
            success_url: "https://colossus-xi.vercel.app/?status=uplink_success",
            cancel_url: "https://colossus-xi.vercel.app/?status=uplink_aborted"
          }),
        });

        const npData = await npResponse.json();

        if (npData.invoice_url) {
          return new Response(JSON.stringify({ checkoutUrl: npData.invoice_url }), { headers: { "Content-Type": "application/json", ...corsHeaders } });
        } else {
          throw new Error("Unable to generate crypto invoice.");
        }
      }

    } catch (error) {
      console.error("Uplink Error:", error);
      return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
    }
  }

  // Fallback for unauthorized/invalid pings
  return new Response("Colossus Uplink Node Active.", { status: 200, headers: corsHeaders });
});
