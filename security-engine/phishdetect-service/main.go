package main

 import (
    "encoding/json"
    "log"
    "net/http"
    "os"

    "github.com/phishdetect/phishdetect"
)

type AnalyzeRequest struct {
	URL string `json:"url"`
}

type AnalyzeResponse struct {
	Score      int      `json:"score"`
	Safelisted bool     `json:"safelisted"`
	Brand      string   `json:"brand"`
	Warnings   []string `json:"warnings"`
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {

	if r.Method != http.MethodPost {
		http.Error(
			w,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		)
		return
	}

	var request AnalyzeRequest

	err := json.NewDecoder(r.Body).Decode(&request)

	if err != nil {
		http.Error(
			w,
			"Invalid JSON",
			http.StatusBadRequest,
		)
		return
	}

	if request.URL == "" {
		http.Error(
			w,
			"URL is required",
			http.StatusBadRequest,
		)
		return
	}

	analysis := phishdetect.NewAnalysis(
		request.URL,
		"",
	)

	analysis.AnalyzeURL()

	warnings := make(
		[]string,
		0,
		len(analysis.Warnings),
	)

	for _, warning := range analysis.Warnings {

		warnings = append(
			warnings,
			warning.Description,
		)
	}

	result := AnalyzeResponse{
		Score:      analysis.Score,
		Safelisted: analysis.Safelisted,
		Brand:      analysis.Brands.GetBrand(),
		Warnings:   warnings,
	}

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(result)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {

	w.Header().Set(
		"Content-Type",
		"application/json",
	)

	json.NewEncoder(w).Encode(
		map[string]string{
			"status":  "ok",
			"service": "CyberShield PhishDetect",
		},
	)
}

func main() {

    http.HandleFunc(
        "/health",
        healthHandler,
    )

    http.HandleFunc(
        "/analyze",
        analyzeHandler,
    )

    port := os.Getenv("PORT")

    if port == "" {
        port = "5003"
    }

    log.Println(
        "PhishDetect service running on port " + port,
    )

    err := http.ListenAndServe(
        "0.0.0.0:"+port,
        nil,
    )

    if err != nil {
        log.Fatal(err)
    }
}