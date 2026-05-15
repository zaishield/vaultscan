-- Apply official ZAISHIELD VAULTSCAN brand identity
-- Reference: BrandGuidelines (v1.0) - dark, sci-fi ops center aesthetic.
-- Colors: Electric Orange #FF6B00 on Void Black #0A0A0A.

UPDATE partner_branding
   SET product_name        = 'ZAISHIELD VAULTSCAN',
       primary_color       = '#FF6B00',
       secondary_color     = '#FF8C00',
       accent_color        = '#0A0A0A',
       legal_footer        = E'ZAISHIELD VAULTSCAN · BRAND v1.0 · CONFIDENTIAL // INTERNAL USE ONLY',
       support_email       = 'support@zaishield.com',
       sender_email        = 'no-reply@zaishield.com',
       sender_name         = 'ZAISHIELD VAULTSCAN',
       watermark_text      = 'CONFIDENTIAL',
       confidentiality_tag = 'CONFIDENTIAL // INTERNAL USE ONLY',
       logo_url            = 'https://media.base44.com/images/public/6a06d2928bbdd80a35ada070/1a018cbab_roamworks_logo_emblem.svg',
       updated_at          = now()
 WHERE partner_id = '00000000-0000-0000-0000-0000000000b1';
