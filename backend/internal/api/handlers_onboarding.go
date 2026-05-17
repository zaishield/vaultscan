// handlers_onboarding.go — partner onboarding checklist readout.
//
// The portal hits GET /api/v1/partners/{partner_id}/onboarding on
// every dashboard render to drive the "X of 6 setup steps left"
// banner. Each milestone is automatically marked complete by the
// matching mutating handler (branding update / domain add / logo
// upload / sender-DNS check / tenant create / support-settings
// PUT), so a partner-admin never has to manually tick a box —
// they just go through the wizard.
package api

import "net/http"

func getPartnerOnboarding(s *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		partnerID, err := uuidParam(r, "partner_id")
		if err != nil {
			badRequest(w, "invalid partner_id")
			return
		}
		st, err := s.Partners.GetOnboarding(r.Context(), partnerID)
		if err != nil {
			internalErr(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"status":           st,
			"percent_complete": st.PercentComplete(),
		})
	}
}
