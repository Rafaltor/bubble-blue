# Tournage Qualcomm University Platforms

Public : page Qualcomm, audience technique générale. Langue parlée : anglais.
Durée finale : sous 8 minutes. 1080p, paysage.

Les slides ne se filment pas. Tu les déposes dans CapCut, Shotcut ou DaVinci.
Fichier : `docs/video/BUBBLE-BLUE-university-platforms.pptx` (12 slides).

Inserts déjà rendus, 1080p, sans son :

- `docs/video/sim-full.mp4` (38 s) — élection du mesh, puis exclusion d’un membre. Même code que les cartes.
- `docs/video/ui-rubik.mp4` (16 s) — la vraie interface, mesh simulé. Carte, message, trajet en jaune. Le bouton privé est visible ; ne le commente pas sur cet insert, le clic n’a pas été fait.

Les plans matériel (5 et 6) seulement si les cartes sont allumées. Sinon tu gardes la phrase, sans le geste.

## Avant d’appuyer sur enregistrer

- Téléphone à l’horizontale, 1080p, grille affichée, horizon bloqué. Pas de zoom en marchant.
- Lumière de face (fenêtre ou softbox). Pas de fenêtre derrière toi.
- Micro près de la bouche. Un micro externe si tu en as un. L’audio était le point faible l’an dernier.
- Une phrase, une prise. Une seconde de silence avant, une après. Tu coupes entre les prises.
- Si un envoi rate, tu refais la prise. Tu ne commentes pas l’échec.
- Les chiffres sont ceux du talk NetMob. Tu n’en ajoutes pas.

## Les prises

| # | ~ | Cadrage | Insert au montage | Tu dis, en anglais |
|---|---|---|---|---|
| 1 | 20 s | Visage, stand derrière si les cartes sont allumées | slide 2 en ouverture, 3 s, sans voix | I’m Paul-Maxence Baraton, at Inria, with Nadjib Achir and Philippe Jacquet. This work is with Wilfred Doré, in the Qualcomm University Platforms program. |
| 2 | 20 s | Visage, ou les cartes sur la table, plan large | slide 3 puis slide 4, 2 s chacune, sous la voix | The case we care about is simple. The cellular network is saturated, or there is no coverage, or you do not want to depend on it. People still need to send a short message. The question is whether a board that is not in the group can carry that message without being able to read it. |
| 3 | 20 s | Gros plan RUBIK Pi, puis gros plan UNO Q. Tu les nommes avec la main, tu ne marches pas. | slide 5 sous la voix, ou à la place du plan si la lumière est mauvaise | Two Qualcomm boards, two roles. The RUBIK Pi 3, a QCS6490, is the screen. The Arduino UNO Q, a QRB2210, with a Qualcomm WCN399x radio, Bluetooth 5.1, is the relay. Same protocol on both. |
| 4 | 20 s | Les deux écrans Rubik et un Arduino entre eux, plan fixe | slide 6 et slide 7, 3 s chacune | The relays dial. The screens do not. There is no Bluetooth pairing. Membership is a key, not a bond. A message between the two screens crosses a relay that is not in the group. |
| 5 | 38 s | Tu ne filmes pas. Tu poses `sim-full.mp4`. | le fichier entier | This is the same code, on eighteen nodes. The mesh elects its relays, and a message crosses them. Then one member is excluded. The next message reaches everyone who remains. That node does not read it. |
| 6 | 25 s | Les deux écrans Rubik dans le cadre, puis le 16×2. Tu appuies sur un message de groupe. Tu attends qu’il arrive. Tu ne parles pas pendant le trajet. | `ui-rubik.mp4` en coupe si l’écran filmé est illisible | A group message. It leaves this screen, it crosses an Arduino, and it is read on the other one. The small display shows the same text. It is a group message. |
| 7 | 20 s | Le bouton Private 1-to-1, puis le 16×2 qui ne change pas. Tu attends. | rien | A private message, from one Rubik to the other. The relay carries it. It does not show it. |
| 8 | 30 s | Visage | slide 8, tenue 4 s sous la deuxième phrase | In the room, seventy-five messages out of seventy-five. Across the building, about fifteen metres, four hops, seventy-six out of seventy-nine. On battery, eight hours and twelve minutes, nine hundred and eighty-eight messages, ninety-nine point seven percent delivered. Median delay, eighty milliseconds. We stopped with the batteries still charged. |
| 9 | 20 s | Visage | slide 9 (3 s) puis slide 10 | What works is the mesh, the group, and the exclusion of one member. What is still open is a sequence counter that survives a restart, and the same link on Android. |
| 10 | 15 s | Visage, ou la table | slide 11 | These boards are enough to measure, not only to show. A room, a building, an afternoon on one charge. The relay radio is a Qualcomm WCN399x. That is what we needed. |
| 11 | 10 s | Visage | slide 12 | The paper is on arXiv, 2509.00967. The code is public. Thank you. |

Parlé : un peu plus de trois minutes. Avec la simulation, l’interface et les silences du message qui voyage, le montage tient entre cinq et six minutes.

## Si les cartes sont éteintes

Tu sautes les prises 6 et 7. À la place, une seule phrase sur la prise 5, après la simulation :

On the stand, a group message shows on every screen. A private message shows only on the two Rubiks. The relay carries it, and does not display it.

Tu gardes `ui-rubik.mp4` en insert sur cette phrase.
