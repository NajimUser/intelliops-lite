
import unittest

from src.contrat import Analyse, Evenement
from src.notification import (
    choisir_canal,
    rediger,
    notifier,
    valider_action,
    tracer_decision,
)


def exemple(sensible=True, niveau="CRITICAL"):
    evt = Evenement(
        "EVT-00125",
        "2026-10-05T10:02:11Z",
        "DOCKER",
        "backend",
        "production",
        "LOG",
        "HIGH",
        "OOMKilled restarts=14",
    )

    analyse = Analyse(
        "EVT-00125",
        niveau,
        "Manque de memoire",
        "Redemarrer le service backend",
        sensible,
        ["DOCKER"],
    )

    return evt, analyse


class TestNotification(unittest.TestCase):

    def test_canaux(self):
        self.assertEqual(choisir_canal("CRITICAL"), "TEAMS")
        self.assertEqual(choisir_canal("HIGH"), "SLACK")
        self.assertEqual(choisir_canal("MEDIUM"), "EMAIL")
        self.assertEqual(choisir_canal("LOW"), "DASHBOARD")

    def test_canal_invalide(self):
        with self.assertRaises(ValueError):
            choisir_canal("UNKNOWN")

    def test_rediger(self):
        evt, analyse = exemple()
        texte = rediger(evt, analyse)

        self.assertIn("[CRITICAL]", texte)
        self.assertIn("Composant : backend", texte)
        self.assertIn("OOMKilled restarts=14", texte)
        self.assertIn("Manque de memoire", texte)
        self.assertIn("Redemarrer le service backend", texte)
        self.assertIn("Sources : DOCKER", texte)
        self.assertEqual(len(texte.splitlines()), 5)

    def test_notifier(self):
        evt, analyse = exemple()
        historique = []

        notif = notifier(evt, analyse, historique)

        self.assertEqual(notif.event_id, "EVT-00125")
        self.assertEqual(notif.channel, "TEAMS")
        self.assertEqual(notif.recipient, "equipe-ops")
        self.assertEqual(len(historique), 1)
        self.assertIs(historique[0], notif)
        self.assertEqual(evt.status, "NOTIFIED")

    def test_validation(self):
        _, analyse = exemple()

        self.assertTrue(valider_action(analyse, " OUI "))
        self.assertTrue(valider_action(analyse, "OK"))
        self.assertTrue(valider_action(analyse, "yes"))
        self.assertTrue(valider_action(analyse, "o"))
        self.assertFalse(valider_action(analyse, "n"))
        self.assertFalse(valider_action(analyse, ""))

    def test_action_non_sensible(self):
        _, analyse = exemple(sensible=False)

        self.assertTrue(valider_action(analyse, "n"))
        self.assertTrue(valider_action(analyse, ""))

    def test_tracer_decision(self):
        _, analyse = exemple()
        journal = []

        decision = tracer_decision(
            analyse,
            True,
            "ops-oncall",
            journal,
            "2026-10-20T15:00:00Z",
        )

        self.assertEqual(decision["event_id"], "EVT-00125")
        self.assertEqual(
            decision["action"],
            "Redemarrer le service backend",
        )
        self.assertTrue(decision["approved"])
        self.assertEqual(decision["actor"], "ops-oncall")
        self.assertEqual(len(journal), 1)
        self.assertIs(journal[0], decision)


if __name__ == "__main__":
    unittest.main()

