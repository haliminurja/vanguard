package models

import (
	"math"
	"strings"
)

func CalculateCVSSv3BaseScore(vector string) float64 {
	metrics := parseCVSSVector(vector)
	if len(metrics) == 0 {
		return 0.0
	}

	av := getMetricWeight(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := getMetricWeight(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	pr := getPRWeight(metrics)
	ui := getMetricWeight(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})
	s := metrics["S"]
	c := getMetricWeight(metrics, "C", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	i := getMetricWeight(metrics, "I", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})
	a := getMetricWeight(metrics, "A", map[string]float64{"H": 0.56, "L": 0.22, "N": 0})

	iss := 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
	var impact float64
	if s == "U" {
		impact = 6.42 * iss
	} else {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15.0)
	}

	exploitability := 8.22 * av * ac * pr * ui

	var baseScore float64
	if impact <= 0 {
		baseScore = 0
	} else if s == "U" {
		baseScore = math.Min(impact+exploitability, 10.0)
	} else {
		baseScore = math.Min(1.08*(impact+exploitability), 10.0)
	}

	return roundUp(baseScore)
}

func parseCVSSVector(vector string) map[string]string {
	parts := strings.Split(vector, "/")
	metrics := make(map[string]string)
	for _, p := range parts {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}
	return metrics
}

func getMetricWeight(metrics map[string]string, key string, weights map[string]float64) float64 {
	if val, ok := metrics[key]; ok {
		if weight, ok := weights[val]; ok {
			return weight
		}
	}
	return 0.0
}

func getPRWeight(metrics map[string]string) float64 {
	s := metrics["S"]
	pr := metrics["PR"]
	if s == "U" {
		switch pr {
		case "N":
			return 0.85
		case "L":
			return 0.62
		case "H":
			return 0.27
		}
	} else if s == "C" {
		switch pr {
		case "N":
			return 0.85
		case "L":
			return 0.68
		case "H":
			return 0.50
		}
	}
	return 0.0
}

func roundUp(v float64) float64 {
	val := math.Round(v * 100000.0)
	if int(val)%10000 == 0 {
		return val / 100000.0
	}
	return (math.Floor(val/10000.0) + 1) / 10.0
}
