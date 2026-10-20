import unittest

from src.analyse import (
    analyser,
    classifier,
    compter_erreurs,
    est_doublon,
    chercher_procedures,
)
from src.contrat import PROCEDURES, Evenement


def evt(
    type_="LOG",
    severity="HIGH",
    message="OOMKilled restarts=14",
    composant="backend",
    timestamp="2026-10-05T10:00:00Z",
):
    return Evenement(
        "EVT-00001",
        timestamp,
        "DOCKER",
        composant,
        "production",
        type_,
        severity,
        message,
    )


class TestAnalyse(unittest.TestCase):

    def test_doublon(self):
        vus = set()
        self.assertFalse(est_doublon(evt(), vus))
        self.assertTrue(est_doublon(evt(), vus))

    def test_erreurs(self):
        compteur = {}
        evenement = evt()

        self.assertEqual(compter_erreurs(evenement, compteur), 1)
        self.assertEqual(compter_erreurs(evenement, compteur), 2)
        self.assertEqual(compteur["backend"], 2)

    def test_erreurs_autre_severite(self):
        compteur = {}
        evenement = evt(severity="LOW")

        self.assertEqual(compter_erreurs(evenement, compteur), 0)
        self.assertEqual(compteur, {})

    def test_erreurs_autre_type(self):
        compteur = {}
        evenement = evt(type_="PIPELINE_FAILURE", severity="HIGH")

        self.assertEqual(compter_erreurs(evenement, compteur), 0)
        self.assertEqual(compteur, {})

    def test_classifier_boucle(self):
        evenement = evt()
        self.assertEqual(classifier(evenement, 3), "CRITICAL")
        self.assertEqual(classifier(evenement, 2), "HIGH")

    def test_classifier_severity(self):
        evenement = evt(severity="LOW")
        self.assertEqual(classifier(evenement), "LOW")

    def test_chercher_procedures(self):
        evenement = evt(message="OOMKilled sur backend")
        resultat = chercher_procedures(evenement, PROCEDURES)

        self.assertTrue(resultat)
        self.assertIn(PROCEDURES["oomkilled"], resultat)

    def test_aucune_procedure(self):
        evenement = evt(message="Service demarre")
        self.assertEqual(chercher_procedures(evenement, {}), [])

    def test_analyser(self):
        evenement = evt()
        resultat = analyser(evenement, PROCEDURES, 1)

        self.assertEqual(resultat.event_id, evenement.id)
        self.assertEqual(resultat.level, "HIGH")
        self.assertEqual(resultat.action, "Surveiller")
        self.assertFalse(resultat.sensitive)
        self.assertEqual(resultat.sources, ["DOCKER"])
        self.assertEqual(evenement.status, "ANALYZED")

    def test_analyser_critical(self):
        evenement = evt()
        resultat = analyser(evenement, PROCEDURES, 3)

        self.assertEqual(resultat.level, "CRITICAL")
        self.assertEqual(
            resultat.action,
            "Redemarrer le service backend",
        )
        self.assertTrue(resultat.sensitive)

    def test_analyser_vulnerabilite(self):
        evenement = evt(
            type_="VULNERABILITY",
            severity="HIGH",
            message="CVE vulnerabilite",
        )
        resultat = analyser(evenement, PROCEDURES)

        self.assertEqual(
            resultat.action,
            "Mettre a jour la dependance backend",
        )
        self.assertFalse(resultat.sensitive)

    def test_analyser_pipeline(self):
        evenement = evt(
            type_="PIPELINE_FAILURE",
            severity="HIGH",
            message="pipeline failed",
            composant="build",
        )
        resultat = analyser(evenement, PROCEDURES)

        self.assertEqual(resultat.action, "Relancer le pipeline build")

    def test_analyser_cause_inconnue(self):
        evenement = evt(message="Service demarre")
        resultat = analyser(evenement, {})

        self.assertEqual(
            resultat.explanation,
            "Cause inconnue : analyse manuelle requise",
        )


if __name__ == "__main__":
    unittest.main()
