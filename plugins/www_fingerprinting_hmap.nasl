#
# (C) Tenable Network Security, Inc.
#

# Redistribution and use in source, with or without modification, are
# permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. All advertising materials mentioning features or use of this software
#    must display the following acknowledgment:
#     This product includes software developed and data gathered by
#     Michel Arboi
#
# This script is not a transcription in NASL of HMAP, which is much
# more complex. It is only based on ideas that are described in
# Dustin Lee's thesis:
# HMAP: A Technique and Tool For Remote Identification of HTTP Servers
#
# hmap.nasl & hmap.py also send different requests: hmap.py includes a
# User-Agent field. In some cases, this produces very different results,
# so signatures from hmap.py cannot be translated for hmap.nasl
#
# To receive useful contributions, we have to generate a significant
# signature for unknown servers. This signature should be compact,
# so only the most significant tests should be selected. An interesting
# side effect is that the plugin will be quicker!
# As I don't have enough web servers, versions, sub-versions, and strange
# or typical configurations, I run into a chicken & egg problem:
# so we must keep in mind that the test set may change, and the known
# signatures will have to be adapted, or recomputed.
#
# NOTE TO SIGNATURE CONTRIBUTORS
# If you have different servers that return the _same_ signature, this
# means that the test has to be enhanced. Please download hmap from
# http://ujeni.murkyroc.com/hmap/ and runs it against your servers, and
# send us the generated files.
#
# To look for duplicated signatures, run:
# egrep '^(...:){20,}' www_fingerprinting_hmap.nasl | awk -F: '{print $1":"$2":"$3":"$4":"$5":"$6":"$7":"$8":"$9":"$10":"$11":"$12":"$13":"$14":"$15":"$16":"$17":"$18":"$19":"$20; }' | sort | uniq -d
#
# Signature contributors:
# Miguel Alfaiate, Chava Alvarez, Greg Armer, Rafael Ausejo Prieto,
# Philipp Babb,J Barger, Alex Bartl, Jochen Bartl,
# Pascal Bederede, Bob T. Berge, Luca Bigliardi, Randy Bias,
# Jorge Blat, Henk Bokhoven, Wayne Boline, Bjorn-Vegar Borge,
# Paul Bowsher, Andrew Brampton, Frank Breedijk, Philip Brooks, Joshua Brown,
# Jeremiah Brott, Dustin Butler, Niels Buttner, Jesus Manuel Carretero,
# James Chenvert, Maciej Cieciera, Joe Clifton, Devin Cofer, Russ Cohen,
# Lionel Cons, Mike Cooper, Owen Crow, Kevin Davidson, Stephen Davies,
# Chuck Deal, Renaud Deraison,
# Peters Devon, Sean Dreilinger, Shaun Drutar, Franck Dubray,
# Thierry Dussuet, Daniel C. Endrizzi, Aizat Faiz, Joshua Fielden,
# Tomasz Finke,
# Stephen Flanagan, Carl Forsythe, Chuck Frain, Dan Frazier, Dennis Freise,
# Scott Fringer,
# Raul Gereanu, Chad Glidden,
# Volker Goller, Thomas Graham, Rick Gray, Matthew Gream, Daniel Griswold,
# Gary Gunderson, Jason Haar, Tim Hadlow, Stuart Halliday,
# Tomi Hanninen, Mads Syska Hansen, Ronny Hansen,
# Chris Hanson, Chris Harrington, Maarten Hartsuijker, Greg Hartwig,
# James Haworth, Jeffrey G Heller, Philip Henderson, Travis Herrmann,
# Rolando Hernandez,
# John Hester, John T Hoffoss, Florian Huber, Thomas Hunter, Fabien Illide,
# Alexander Isaenko, Ron Jackson, Jay Jacobson,
# Simen Graff Jenssen, Bill Johnson, Eric Johnson, Paul Johnston,
# Maciek Jonakowski, Michiel Kalkman, Mats Karlsson,
# Imre Kaloczi, Pavel Kankovsky, Boris Karnaukh, Egon Kastelijn,
# James M. Keller, Eddie Kilgore, Don M. Kitchen, Yuval Kogman,
# Robert Kolaczynski, Michael Kohne, Jerzy Yuri Kramarz, Pierre Kroma,
# Nerijus Krukauskas,
# Paul Kurczaba, David Kyger, Andre Lewis, Tarmo Lindstrom,
# Sebastien Louafi, Mark Lowe, Richard Lowe, Stephane Lu, Darcey MacInnes,
# Martin Maeok, Florin Mariuteac, Raul Mateos Martin,
# Mats Martinsson, Thomas Maurer, Zul Mohd, Mick Montgomery, Greg Mooney,
# Samuel Morais, Jose Manuel Rodriguez Moreno, Mike Nelson, Michel Nolf,
# Kevin O'Brien, Warren Overholt, C. Paparelli, Eric F Paul, Ashesh Patel,
# Juraj Pazican, Marc Pinnell, Nicolas Pouvesle,
# Federico Petronio, John Pignata, Abri du Plooy, Xavier Poli, Dave Potts,
# Matthew Pour, Sally Pryor, Mike Pursifull,
# Jason Radley, Jim Rather, Dmytro O. Redchuk, Mark Rees,
# Thomas Reinke, Cas Renooij, Jon Repaci, Ruben Rickard,
# Iben Rodriguez, Brooks Rosenow,
# Mark Sayer, Michael Scheidell, Tom Shockley, Frank Schreiner, Don Senzig,
# Beat Siegenthaler, Barn Ski, Charles Skoglund, Adam Smith, Glenn Smith,
# Maurice Smulders, Marco Spoel, Ricardo Stella, Andra Steiner,
# Charlie Stigler, Iain Stirling,
# Marius Strom, Jason Sullivan, Robby Tanner, Jimmy Tharel,
# George A. Theall, Adam Thompson, Massimo Trevisani,
# Ralph Utz, Mattias Webjorn Eriksson, Patrick Webster, Mikael Westerlund,
# Curt Wilson, Brad Williamson, Jeremy Wood, Bruce Wright,
# Jeffrey Yu, Paolo Zavalloni, Thorsten Zenker, Andrew Ziem,
# Asmodianx, Crowley, Daniel, Empire Strikes Back, Ffoeg, The Frumster,
# Joe pr, jfvanmeter, Masakatsu Agatsu, mjnsecurity, Mofo63,
# Munkhbayar, Neo, Noisex, Pavel, Podo, PoiS QueM, Silencer, Stephan,
# Sullo, Vitaly, Yanli-721, Yong, Alexandre Roberto Zia, Zube
#
# If I forgot you in this list or misspelled your name (or nym),
# please tell me!
#
# Unused / unknown / imprecise signatures:
# ---:200:405:---:---:---:---:VER:---:200:---:---:200:---:---:---:---:+++:400:405:405:405:405:405:+++:^$:[EMC]

include("compat.inc");

if (description)
{
  script_id(11919);
  script_version("$Revision: 1.786 $");
  script_cvs_date("$Date: 2017/05/26 23:59:56 $");

  script_name(english:"HMAP Web Server Fingerprinting");
  script_summary(english:"Fingerprints the web server.");

  script_set_attribute(attribute:"synopsis", value:
"HMAP fingerprints the remote HTTP server.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote web server type by sending
several valid and invalid HTTP requests. In some cases, its version
can also be approximated, as well as some options.");
  # https://web.archive.org/web/20031010044806/http://ujeni.murkyroc.com/hmap/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?05d4ce87");
  script_set_attribute(attribute:"see_also", value:"http://seclab.cs.ucdavis.edu/papers/hmap-thesis.pdf");
  script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246925/Fingerprinting");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc. - HMAP research by Dustin Lee");
  # Maybe I should add a timeout: this script can be very slow against
  # some servers (4m20s against u-server-0.x)

  # Do NOT add http_version.nasl, this would create circular dependencies
  script_dependencie("find_service1.nasl", "http_login.nasl", "httpver.nasl", "no404.nasl", "embedded_web_server_detect.nasl", "broken_web_server.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

#### Fingerprints
# The last field is the name of the server, the previous field is the regex
# that the "Server" field is supposed to match.
# If the regex field is empty, the last field MUST be equal to the banner
#
# +++ is a joker than matches anything (useful when we add requests)
# --- means no answer
# HTM means that the server returned HTML directly, without any clean HTTP
# answer code & headers.
# VER means that the server answered with an invalid HTTP version, e.g.:
#    HTTP/3.14
#    HTTP/1.X
#    HTTP/
#    http/1.0
# Note that this last code was added recently, and that previous signature
# may contain xxx instead in 4th, 5th, 6th or 8th position, or a valid
# numeric code only in 6th or 8th position in some rare cases (when the
# server answered with HTTP/ or http/1.0 in lower case)
#
# Last but not least, do not insert ':' characters in the description fields.
# For example, see WebLogic.

fingerprints = "
+++:xxx:200:505:400:302:302:400:400:400:400:400:404:404:404:200:404:404:+++:+++:::2Wire-Gateway/Shasta
+++:200:404:200:200:200:404:404:404:404:404:200:404:404:404:404:404:404:+++:+++::^$:One port print server (GP-100P) by ConnectGear
# More precise but conflicting signature
200:200:404:200:200:200:404:404:404:404:404:200:404:404:404:404:404:404:404:404:::Techno Vision Security System Ver. 2.0
#
# The switch was running OS version 3.21, hardware version 07.01.01, Boot Version 2.21
+++:200:400:200:200:400:400:400:400:200:200:200:200:200:200:400:400:400:+++:+++:3Com/v1.0::3Com/v1.0 [SuperStack 3 Switch 4400 (3C17204)]
# 3Com SuperStack 3 Switch 3300XM Hardware Version:  0 Software Version:  2.72
200:200:400:200:200:400:400:400:400:200:200:200:200:200:200:400:400:400:500:500:::3Com/v1.0 [SuperStack 3 Switch 3300XM V2.72]
200:404:404:200:200:404:404:404:404:404:404:200:---:404:404:404:404:404:404:404:::3ware/2.0 [3DM2]
400:404:405:505:200:405:405:405:405:404:404:200:+++:404:405:405:405:405:+++:+++::^$:HP Switch [unknown model?]
---:---:---:---:---:---:---:---:---:404:---:200:---:---:---:---:---:---:404:404:::eHTTP v2.0 [HP ProCurve Switch 2810-48G]
# 3ComR OfficeConnectR Wireless 11g Access Point / Product #: 3CRWE454G72 / Software version 1.03.12 / Boot loader version 1.00.02 / Wireless version V1.0.3.0 / Hardware version 01A
+++:---:---:200:---:500:---:---:---:---:---:500:+++:400:400:400:400:400:+++:+++::^$:3ComR OfficeConnectR Wireless 11g Access Point
# There are two Abyss web server...
# from abyss.sourceforge.net
+++:200:400:505:400:400:200:500:500:400:400:200:405:405:405:405:405:405:400:+++:::ABYSS/0.3
# Abyss/1.2.1.0 (Linux) AbyssLib/1.0.7 # from www.aprelium.com
# Abyss/1.2.3.0-Win32 AbyssLib/1.1.0
+++:HTM:HTM:505:HTM:HTM:200:HTM:HTM:HTM:HTM:200:404:404:404:404:404:404:200:+++:Abyss/1.2:^Abyss/1\.2\.[1-3]\.:Abyss/1.2.1.0-3 (Linux/Win32)
+++:HTM:HTM:505:HTM:HTM:200:HTM:HTM:HTM:HTM:200:302:302:302:302:302:302:200:+++:Abyss/1.1::Abyss/1.1.6 (Win32) AbyssLib/1.0.7
+++:HTM:---:---:---:---:200:---:---:---:---:200:404:404:404:404:404:404:200:+++:Abyss/2.0 (Win32)::Abyss/2.0.6-X1-Win32 AbyssLib/2.0.6
# Conflicting & more precise
# Abyss/2.5.0.0-X1-Win32 AbyssLib/2.5.0.0
# Abyss/2.6.5-X1-Win32 AbyssLib/2.6.4.0#
HTM:HTM:---:---:---:---:200:---:---:---:---:200:404:404:404:404:404:404:200:404:Abyss/2.5 (Win32) or Abyss/2.6 (Win32):^Abyss/2\.[56]\.[05](\.0)?-X1-Win32 AbyssLib/2\.[56]\.[04]\.0:Abyss/2.5-2.6.5 Win32 AbyssLib/2.5.0.0 -2.6.4.0
#
+++:HTM:400:VER:VER:VER:200:---:---:400:501:400:+++:404:404:404:404:404:+++:+++:::Acme.Serve/v1.7 of 13nov96
HTM:HTM:400:VER:VER:VER:200:---:---:400:501:400:404:404:404:404:404:404:200:404:::Acme.Serve/v1.7 of 13nov96
---:---:400:VER:VER:VER:---:---:---:400:501:400:404:404:404:404:404:404:403:404:::Acme.Serve/v1.7 of 13nov96
#
+++:200:---:200:200:---:200:200:200:200:+++:200:404:---:---:---:---:---:+++:+++:::ADSM_HTTP/0.1
+++:200:400:200:200:200:400:400:400:200:400:200:+++:501:400:400:400:400:+++:+++:::Agent-ListenServer-HttpSvr/1.0
200:200:400:200:200:200:400:400:400:200:400:200:501:501:400:400:400:400:403:403:::Agent-ListenServer-HttpSvr/1.0
+++:200:400:200:200:200:400:400:400:200:200:200:+++:400:400:400:400:400:+++:+++:::McAfee-Agent-HttpSvr/1.0
+++:200:400:200:200:200:400:400:400:200:200:200:501:501:400:400:400:400:+++:+++::^Agent-ListenServer-HttpSvr/1\.0$:McAfee ePolicy Orchestrator Agent version 3.1.0.211
+++:200:400:200:200:200:400:400:400:200:400:200:501:501:400:400:400:400:400:+++::^Agent-ListenServer-HttpSvr/1\.0$:McAfee ePolicy Orchestrator Agent version 3
# More precise
200:200:400:200:200:200:400:400:400:200:400:200:501:501:400:400:400:400:400:400::^Agent-ListenServer-HttpSvr/1.0$:McAfee ePolicy Orchestrator Agent version 3.1.2.257
# mCAT(TM) is an realtime operating system for use in embedded system.
# It is a original design of mocom software GmbH & Co KG, Aachen,
# Germany. mCAT supports ARM-Plattforms.
+++:400:501:200:400:501:200:501:400:200:501:200:404:501:501:501:501:501:+++:+++:::mCAT-Embedded-HTTPD
# hardware device (Allegro-Software-RomPager) embedded in an APC UPS controller card
# http://archives.neohapsis.com/archives/ntbugtraq/2000-q2/0223.html
+++:200:200:200:200:405:405:405:405:404:+++:---:---:405:405:---:---:405:+++:+++:::Allegro-Software-RomPager/2.10
#
+++:200:404:400:400:400:400:400:400:400:404:200:404:404:404:404:400:400:400:+++:AllegroServe/1.2:^AllegroServe/1\.2\.[34]:AllegroServe/1.2.37 to 1.2.42
# APC Web/SNMP Management Card
# (MB:v3.3.2 PF:v1.1.0 PN:apc_hw02_aos_110.bin AF1:v1.1.1 AN1:apc_hw02_sumx_111.bin MN: AP9617 HR: A10 SN: JA0243028055 MD:10/25/2002)
# (Embedded PowerNet SNMP Agent SW v2.2 compatible)
+++:200:200:200:200:405:405:405:405:404:404:400:400:405:405:200:405:405:+++:+++:Allegro-Software-RomPager/3::Allegro-Software-RomPager/3.10
# CISCO IP Phone 7940 series
400:400:405:200:200:405:405:405:405:404:404:400:400:405:405:405:405:405:400:400:Allegro-Software-RomPager/3::Allegro-Software-RomPager/3.12 [CISCO IP Phone CP-7940G]
+++:200:405:200:200:405:405:405:405:404:404:400:400:405:405:405:405:405:400:+++:Allegro-Software-RomPager/3::Allegro-Software-RomPager/3.12 [CISCO IP Phone 7940 series]
# Conflicting signature
200:200:405:200:200:405:405:405:405:404:404:400:+++:405:405:405:405:405:+++:+++:Allegro-Software-RomPager/4::Allegro-Software-RomPager/4.31
# Raw signature
+++:400:200:401:401:405:405:405:405:404:404:400:+++:405:405:405:405:405:+++:+++:Allegro-Software-RomPager/4::Allegro-Software-RomPager/4.04
# Allegro-Software-RomPager/4.06
# RomPager/4.07 UPnP/1.0
+++:200:405:200:200:405:405:405:405:404:404:400:400:400:405:405:405:405:400:+++:Allegro-Software-RomPager/4:^(Allegro-Software-)?RomPager/4\.0[67]:Allegro-Software-RomPager/4.06-4.07
# amuleweb is very close to Kerio Personal FW
200:---:---:200:200:---:---:---:---:200:---:200:---:---:---:---:---:---:200:+++:::aMule
+++:200:400:200:200:400:401:401:401:401:400:200:400:400:400:400:400:400:+++:+++::^$:Ambit DOCSIS Cable Modem
+++:200:200:200:200:501:400:400:400:200:400:400:501:404:404:501:501:501:400:+++:::AnWeb/1.40d
+++:200:404:200:200:501:400:400:400:200:400:400:501:404:404:501:501:501:400:+++::^AnWeb/1\.4[12][a-p]:AnWeb/1.41g-1.42p
200:200:404:200:200:501:400:400:400:200:400:400:501:404:404:501:501:501:400:400:::AnWeb/1.42p
# Apt-proxy 1.2.9.2
# Apt-proxy 1.3.6 (OS: Debian unstable / Kernel: Linux 2.6.4 with grsecurity 2.0)
+++:200:---:200:200:200:200:---:---:200:---:200:---:---:---:---:---:---:+++:+++:Apt-proxy:^Apt-proxy 1\.[23]\.:Apt-proxy 1.2.9.2 - 1.3.6
# AXIS 540+/542+ Network Print Server V6.00 Jul  5 1999.
# AXIS 540+/542+ print servers with OS versions of V5.55 and V5.51
# have the same signature.
+++:400:400:200:200:200:200:400:400:200:404:200:404:400:400:400:400:400:+++:+++::^$:AXIS 540+/542+ Network Print Server
+++:200:501:HTM:HTM:501:501:501:501:400:400:200:404:501:501:501:501:501:+++:+++::^$:AXIS 205 version 4.03 Webcam
+++:401:---:401:401:---:---:---:---:401:200:401:---:---:---:---:---:---:404:+++::^$:AXIS 200+ Webcam
+++:VER:404:401:401:VER:VER:VER:---:404:404:401:404:404:404:404:VER:VER:401:+++::^$:Panasonic BB-HCM311A Webcam
200:VER:404:200:200:VER:VER:VER:---:404:404:200:404:404:404:404:VER:VER:200:404::^$:panasonic BB-HCM381 Webcam v1.08
+++:404:---:200:200:200:200:---:---:404:+++:200:404:---:---:---:---:---:+++:+++:::3ware/1.0
# Device: Efficient 5865 DMT-ISDN Router (5865-002) v5.3.90 Ready
+++:xxx:400:505:400:200:200:400:400:400:400:200:404:404:404:404:404:404:+++:+++:Agranat-EmWeb/R4::Agranat-EmWeb/R4_01
# Netscreen-5XT 10 user with OS NS5rc04
+++:HTM:200:505:400:200:200:400:400:400:400:400:303:405:405:200:405:405:+++:+++:Agranat-EmWeb/R6::Virata-EmWeb/R6_0_1
# Juniper ScreenOS 6.3.0
---:---:---:505:400:---:200:400:---:400:400:400:303:405:405:---:405:405:---:---:Juniper ScreenOS 6:^Virata-EmWeb/R6_0_1:Juniper ScreenOS 6
HTM:HTM:200:505:400:200:200:400:400:400:400:400:303:405:405:405:405:405:---:---:Juniper ScreenOS 6:^Virata-EmWeb/R6_0_1:Juniper ScreenOS 6
# Agranat-EmWeb/R5_2_6
# Virata-EmWeb/R6_2_1
+++:HTM:200:505:400:200:200:400:400:400:+++:400:404:404:404:200:404:404:+++:+++:Agranat-EmWeb/R5 or Virata-EmWeb/R6:^(Agranat|Virata)-EmWeb/R[56]_2_[16]:Agranat-EmWeb/R5_2_6 or Virata-EmWeb/R6_2_1
# More precise!
# From 3com nbx 100 voip call manager. vxworks os, 3com nbx firmware v 4_2_7
+++:HTM:200:505:400:200:200:400:400:400:400:400:404:404:404:200:404:404:+++:+++:Virata-EmWeb/R6::Virata-EmWeb/R6_0_3
# Conflicts with next signatures
xxx:xxx:200:505:400:200:200:400:400:400:400:400:404:404:404:200:404:404:200:404:Virata-EmWeb/R6::Nucleus/4.3 UPnP/1.0 Virata-EmWeb/R6_2_0
# Less precise - From Lucent Technologies Cajun P333 R
+++:xxx:200:505:400:200:200:400:400:400:400:400:404:404:404:200:404:404:404:+++:Agranat-EmWeb/R5::Agranat-EmWeb/R5_1_2
# Less precise than above - might be the same
+++:xxx:200:505:400:200:200:400:400:400:400:400:404:404:404:200:404:404:+++:+++:Virata-EmWeb/R6::Virata-EmWeb/R6_0_1
+++:HTM:200:505:400:200:200:400:400:400:400:400:405:405:405:200:405:405:+++:+++:Virata-EmWeb/R5:Virata-EmWeb/R5_3_0:Cisco VPN 3000 Concentrator Series Manager (Virata-EmWeb/R5_3_0)
+++:HTM:200:505:400:200:200:400:400:400:400:400:200:405:405:200:405:405:+++:+++:Virata-EmWeb/R5:Virata-EmWeb/R5_3_0:Cisco VPN 3000 Concentrator Series Manager (Virata-EmWeb/R5_3_0)
# AOL application server
+++:HTM:404:200:HTM:HTM:200:400:400:404:200:200:404:404:404:404:404:404:200:+++:AOLserver/3:^AOLserver/3\.[3-5]\.:AOLserver/3.3.1 to 3.5.6
+++:HTM:404:200:HTM:HTM:200:---:---:200:+++:+++:404:404:404:404:404:404:+++:+++:AOLserver/4:AOLserver/4\.:AOLserver/4.0
#
---:---:302:302:400:505:200:HTM:HTM:400:400:400:302:302:302:302:302:302:200:200:Vulture:Apache:Vulture rever proxy on Apache/2.2
## Is this real? ##
# Apache/1.0.0
# Apache/1.0.5
+++:HTM:400:200:200:501:HTM:HTM:HTM:400:400:200:501:501:501:501:501:501:200:+++:Apache/1.0:^Apache/1\.0\.[0-5]:Apache/1.0.0 to 1.0.5
+++:HTM:400:200:200:501:HTM:HTM:HTM:400:400:200:501:501:501:501:501:501:403:+++:Apache/1.0::Apache/1.0.3
+++:HTM:400:200:200:200:HTM:HTM:HTM:400:400:400:501:501:501:501:501:501:200:+++:Apache/1.1::Apache/1.1.1
+++:HTM:400:200:200:501:HTM:HTM:HTM:400:400:400:501:501:501:501:501:501:403:+++:Apache/1.1:^Apache/1\.1\.[1-3]:Apache/1.1.1 to 1.1.3
# Stronghold/1.3.4 Ben-SSL/1.3 Apache/1.1.3
+++:HTM:400:200:200:501:HTM:HTM:HTM:400:400:400:501:501:501:501:501:501:200:+++:Apache/1.1:^([A-Za-z_-]+/[0-9.]+ )?Apache/1\.1\.[1-3]$:Apache/1.1.1 to 1.1.3
+++:HTM:400:200:200:501:HTM:HTM:HTM:400:400:400:501:501:501:501:501:501:302:+++:Apache/1.1::Apache/1.1.3
# Stronghold/2.2 Apache/1.2.5 C2NetEU/2048-custom
# IBM_HTTP_Server/1.3.3.2 Apache/1.3.4-dev (Unix)
# IBM_HTTP_Server/1.3.3.3 Apache/1.3.4-dev (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2 (Unix) or Apache/1.3 (Unix):^Apache(/1\.(2\.[0-6]|3\.0|3\.4-dev).*)?$:Apache/1.2.0 to 1.3.4-dev
# Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.2b10
# Stronghold/2.1 Apache/1.2.4 UKWeb/2046
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:200:+++:Apache/1.2 (Unix) or Apache/1.3 (Unix):^Apache(/1\.(2\.([0-6]|[ab][0-9]+)|3\.[0-3]).*)?$:Apache/1.2.0 to 1.3.3
#
+++:HTM:200:200:200:501:200:HTM:---:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2::Apache/1.2.0
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:302:200:501:501:200:+++:Apache/1.2::Apache/1.2.1
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:200:200:501:501:200:+++:Apache/1.2::Apache/1.2.4
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:403:403:200:501:501:403:+++:Apache/1.2::Apache/1.2.6 FrontPage/3.0.4.1
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2::Apache/1.2.6 secured_by_Raven/1.2
+++:400:200:200:200:200:200:400:400:400:400:200:404:405:400:200:400:400:403:+++:Apache/1.2::Apache/1.2.6.46 WebTen/3.0 SSL/0.9.0b
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:501:501:403:+++:Apache/1.2:^Apache/1\.2\.[4-6]:Apache/1.2.4 to 1.2.6
+++:xxx:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:200:+++:Apache/1.2::Apache/1.2.4
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:403:403:403:200:501:501:403:+++:Apache/1.2::Apache/1.2.4
+++:HTM:200:200:403:403:403:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2::Apache/1.2.4 FrontPage/3.0.3
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:404:200:501:501:200:+++:Apache/1.2::Apache/1.2.4 mod_perl/1.02
# Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.2.4 PHP/FI-2.0
# Stronghold/2.2 Apache/1.2.5 C2NetUS/2002/php3.0.3
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:501:501:200:+++:Apache/1.2 (Unix) or Apache/1.3 (Unix):^([A-Za-z/0-9_.-]+ +)?Apache(/1\.(2\.[4-6]|3\.[0-3]).*)?$:Apache/1.2.4 to 1.3.3 (Unix)
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2::Apache/1.2.4 rus/PL20.5
+++:---:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:501:501:200:+++:Apache/1.2::Apache/1.2.4 PHP/FI-2.0
# Apache/1.2.5
# Apache/1.2.6 Red Hat
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:501:501:200:+++:Apache/1.2 (Unix):^Apache(/1\.2\.[56] .*)?$:Apache/1.2.5-6 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:302:302:200:501:501:302:+++:Apache/1.2 (Unix)::Apache/1.2.5 FrontPage/3.0.4
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:302:200:501:501:403:+++:Apache/1.2 (Unix):^Apache/1\.2\.[56]:Apache/1.2.5 or 1.2.6
+++:xxx:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2 (Unix)::Apache/1.2.6
+++:HTM:200:200:200:302:200:HTM:HTM:302:302:302:302:302:302:200:302:302:302:+++:Apache/1.2 (Unix)::Apache/1.2.6 FrontPage/3.0.4.1
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:302:405:302:200:501:501:200:+++:Apache/1.2 (Unix)::Apache/1.2.6 Red Hat
+++:BLK:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:+++:Apache/1.2 (Unix)::Apache/1.2.6
# Apache/1.2.6 KK-NET wpp/1.0
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:403:403:200:501:501:403:+++:Apache/1.2 (Unix)::Apache/1.2.6
+++:HTM:200:200:302:302:302:HTM:HTM:302:302:400:200:405:200:200:501:501:302:+++:Apache/1.2 (Unix)::Apache/1.2.6 Ben-SSL/1.16 FrontPage/3.0.4
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:405:405:405:200:501:501:200:+++:Apache/1.2 (Unix)::Apache/1.2b6
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:405:405:405:200:501:501:403:+++:Apache/1.2 (Unix)::Apache/1.2b7
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:302:+++:Apache/1.2 (Unix)::Apache/1.2b10
#
+++:HTM:403:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.20 (Trustix Secure Linux/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.1.0
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:+++:Apache/1.3 (Unix)::Apache/1.3.20 (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_jk/1.2.1 PHP/4.3.6 AuthMySQL/2.20 Resin/1.2.0
# Apache/1.3.29 Ben-SSL/1.53 (Debian GNU/Linux) PHP/4.3.4
# Apache/1.3.27 (Trustix Secure Linux/Linux) PHP/3.0.18
# Apache/1.3.33 (Unix) Resin/2.1.14 mod_ssl/2.8.22 OpenSSL/0.9.7d PHP/4.3.9
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-3]):Apache/1.3.27-33 (Linux)
# Apache/1.3.31 (Unix)
# Apache/1.3.27 (Trustix Secure Linux/Linux) PHP/4.0.6
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:+++:Apache/1.3 (Unix):^Apache/1.3.(2[7-9|3[01]):Apache/1.3.27-31 (Unix)
# Apache/1.3.33 Ben-SSL/1.55 (Debian GNU/Linux) PHP/4.3.10-18 mod_perl/1.29
# Apache/1.3.33 (Trustix Secure Linux/Linux) DAV/1.0.3
# Apache/1.3.34 (Debian) mod_jk/1.1.0 mod_ssl/2.8.25 OpenSSL/0.9.8a
# Apache/1.3.27 (Trustix Secure Linux/Linux)
+++:XML:200:200:400:501:200:HTM:XML:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-3]) .*\([A-Za-z /]*Linux|Debian\):Apache/1.3.27-33 (Linux)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.0.6 mod_perl/1.26 mod_throttle/3.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) Carrot-1.0.7 PHP/4.3.0 mod_perl/1.21
#HTM:200:200:200:400:400:HTM:400:400:200:HTM:HTM:200:400:400:+++:400:404:403:403:200:200:404:501:+++:Apache/1.3.22 (Unix)  (Red-Hat/Linux)
# Apache/1.3.26 (Unix) PHP/4.2.3 mod_perl/1.26
# Apache/1.3.26 (Unix) PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6b PHP/4.1.2 mod_throttle/3.1.2
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.2[2-6] \(Unix\) .*PHP/4\.:Apache/1.3.22-26 (Unix) PHP/4
+++:HTM:200:200:400:400:200:HTM:HTM:400:+++:400:404:200:200:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_perl/1.23
# Apache/1.3.23 (Unix) PHP/4.1.2
# Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.22
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.(1[2-9]|2[0-3]) \(Unix\):Apache/1.3.12-23 (Unix)
#
+++:HTM:200:200:403:501:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.14 (Unix) Resin/2.1.4 PHP/4.0.4pl1
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:400:+++:Apache/1.3 (Unix)::Apache/1.3.20 (Unix) Resin/2.1.1 mod_ssl/2.8.4 OpenSSL/0.9.4
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.14 (Unix) PHP/4.3.4 rus/PL30.0
# Apache/1.3.23 (Unix) PHP/4.1.0
# Apache/1.3.24 (Unix) PHP/4.2.3 rus/PL30.12
# Apache/1.3.20 Sun Cobalt (Unix)
# Apache/1.3.20 (Linux/SuSE) mod_perl/1.26 mod_ssl/2.8.4 OpenSSL/0.9.6b
# Apache/1.3.12 (Unix) Resin/1.2.0
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^(Oracle9iAS/9.0.2.3.0 Oracle HTTP Server|Apache/1\.3\.(1[2-9]|2[0-4]) .*\(Unix|Linux[/A-Za-z]*\)):Apache/1.3.12-24 (Unix) [might be Oracle HTTP Server]
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b PHP/4.1.2 mod_throttle/3.1.2
# Apache/1.3.31 (Unix) PHP/4.3.8
# Apache/1.3.31
# Apache/1.3.31 (Unix) PHP/4.3.6
# Apache/1.3.33 (Debian GNU/Linux)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9|3[0-3]) \(Unix|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/1.3.27-33 (Unix)
+++:HTM:200:200:400:500:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) mod_jk/1.2.1 mod_ssl/2.8.19 OpenSSL/0.9.7d
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.23 (Unix) DAV/1.0.3 PHP/4.3.3
+++:HTM:200:200:200:501:200:HTM:HTM:---:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.23 (Unix)  (Red-Hat/Linux) Resin/2.1.3 mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:403:403:403:403:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
# Apache/1.3.26 (Unix) mod_ssl/2.8.9 OpenSSL/0.9.6b rus/PL30.14
# Apache/1.3.26 (Unix) Resin/2.0.2 PHP/4.3.2
+++:---:200:200:400:400:200:HTM:---:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:403:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
+++:HTM:200:200:400:501:200:HTM:HTM:400:301:400:404:403:403:403:501:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) mod_accel/1.0.30 mod_deflate/1.0.19 mod_ssl/2.8.15 OpenSSL/0.9.7a
+++:HTM:200:200:400:403:200:HTM:HTM:400:301:400:404:405:403:200:403:403:403:+++:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) mod_accel/1.0.30
+++:HTM:200:200:400:406:406:HTM:HTM:400:400:400:406:405:404:200:404:501:406:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) PHP/4.3.7
# Apache/1.3.31 (Unix) mod_jk/1.2.5 FrontPage/5.0.2.2635 mod_fastcgi/2.4.2 mod_throttle/3.1.2 PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.27 OpenSSL/0.9.6 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.31 (Unix) FrontPage/5.0.2.2510
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[01]) .*\(Unix\):Apache/1.3.27-31 (Unix)
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)
+++:HTM:200:200:400:501:200:HTM:HTM:302:302:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) mod_jk/1.2.2 mod_ssl/2.8.14 OpenSSL/0.9.7a
+++:HTM:403:200:400:200:200:HTM:HTM:400:400:400:200:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) PHP/4.2.3
# Apache/1.3.31 (Unix) mod_ssl/2.8.19 OpenSSL/0.9.7d PHP/4.3.8
# Apache/1.3.31 (Debian GNU/Linux) mod_jk/1.2.2-dev
# Apache/1.3.28 (Unix) PHP/4.3.7
# Apache/1.3.27
+++:HTM:200:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[789]|3[01])( \(Unix|[A-Za-z/ ]*Linux\).*)?$:Apache/1.3.27-31 (Unix)
+++:xxx:200:200:400:200:200:xxx:xxx:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) Resin/2.1.10 mod_throttle/3.1.2 mod_ssl/2.8.19 OpenSSL/0.9.7d
+++:HTM:404:200:400:501:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Debian GNU/Linux) PHP/4.3.3 mod_ssl/2.8.9 OpenSSL/0.9.6g
# Apache/1.3.29 (Debian GNU/Linux) mod_gzip/1.3.26.1a mod_perl/1.29 PHP/4.3.4
# Apache/1.3.27 (Unix) (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.33 (ALT Linux/alt1) PHP/4.3.10-ALT
# Apache/1.3.34 (Debian) PHP/4.4.2-1.1
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-4]):Apache/1.3.27-33 (Unix)
# Apache on Brocade Switch with Fabric OS 6.4.1b
HTM:HTM:200:200:400:400:400:HTM:HTM:400:400:400:404:405:405:403:405:501:400:404:Apache:^Apache:Apache on Brocade Switch with Fabric OS
# Apache-AdvancedExtranetServer
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) PHP/4.1.2 mod_ssl/2.8.7 OpenSSL/0.9.6c
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.1mdk) mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.3.90mdk) FrontPage/5.0.2.2623 PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.3.4
# Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache(-AdvancedExtranetServer)?(/1\.3\.2[2-6].*)?$:Apache/1.3.22-26 (Unix)
+++:HTM:200:200:400:400:200:HTM:HTM:400:+++:400:404:404:404:200:404:404:+++:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) mod_perl/1.27 PHP/4.2.2
+++:HTM:403:200:400:400:200:HTM:HTM:400:+++:400:403:403:403:200:403:403:+++:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) mod_fastcgi/2.2.12
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix):^Apache(/1\.3\.26.*)?$:Apache/1.3.26 (Debian 3.0 woody)
+++:xxx:200:200:400:200:200:xxx:xxx:400:400:400:404:405:405:200:501:501:200:+++:Apache/1.3 (Unix)::IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Unix)
# Apache/1.3.26 (Darwin) PHP/4.1.2 mod_perl/1.26
# Apache/1.3.26 (Unix)
# Apache/1.3.26 Ben-SSL/1.48 (Unix) PHP/4.2.3
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.26 .*\((Unix|Darwin|[A-Za-z ]*Linux)\):Apache/1.3.26 (Unix)
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.3.0 mod_perl/1.26
# Apache/1.3.26 (Unix) mod_throttle/3.1.2 PHP/4.0.6
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.2[2-6] \(Unix\):Apache/1.3.22-26 (Unix)
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:403:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) FrontPage/5.0.2.2623
+++:HTM:403:200:400:400:200:HTM:HTM:200:200:400:200:403:403:200:403:403:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux mod_ssl/2.8.9 OpenSSL/0.9.6c mod_perl/1.26
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:302:401:401:200:401:401:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.3.4 AuthMySQL/3.1 DAV/1.0.3
#
+++:---:200:200:200:501:200:HTM:---:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.12 (Unix)  (SuSE/Linux) mod_fastcgi/2.2.2 mod_perl/1.24 PHP/4.2.2 mod_ssl/2.6.5 OpenSSL/0.9.5a
# Apache/1.3.29
# Apache/1.3.28 (Unix) PHP/4.3.3 on FreeBSD 4.9 x86, default install
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Unix)
# IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Unix)
# Apache/1.3.27 (NETWARE)
# Apache/1.3.27 OpenSSL/0.9.6 (Unix)
# Apache/1.3.27 (Unix) PHP/4.1.2 ApacheJServ/1.1.2
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.4
# Apache/1.3.31 (Unix) PHP/4.3.6 mod_ssl/2.8.17 OpenSSL/0.9.7d rus/PL30.20
# Apache/1.3.33 (Unix)
# Apache/1.3.34 (Unix) PHP/4.4.1
# Apache/1.3.36 (Unix) mod_jk/1.2.5 DAV/1.0.3 PHP/4.4.2 mod_perl/1.29
# Apache/1.3.36 (Unix) mod_perl/1.26 mod_gzip/1.3.26.1a PHP/4.4.2 mod_ssl/2.8.27 OpenSSL/0.9.8b
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7e-p1
# Apache/1.3.37 (Unix) PHP/4.4.4 mod_ssl/2.8.28 OpenSSL/0.9.8d
# Apache/1.3.37 (Unix) PHP/4.4.4 PHP/3.0.18-i18n-ja-3
# Apache/1.3.37 (Unix) PHP/4.4.4 mod_ssl/2.8.28 OpenSSL/0.9.7c FrontPage/5.0.2.2635
# Apache/1.3.37 (Unix) PHP/5.2.0 with Suhosin-Patch
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix) or Apache/1.3 (Netware):Apache/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-37 (Unix/Netware)
+++:HTM:200:200:400:400:---:---:---:400:400:400:404:405:404:200:400:400:403:+++:Apache/1.3 (Unix)::IBM_HTTP_SERVER/1.3.26.2 Apache/1.3.26 (Unix)
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.31 (Trustix Secure Linux/Linux)
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:+++:Apache/1.3 (Unix):^Apache(/1\.3\.(2[89]|3[01]).*)?$:Apache/1.3.28-31 (Unix)
# Apache/1.3.31 (Unix) PHP/4.3.7 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.29 Ben-SSL/1.52 (Debian GNU/Linux) mod_perl/1.29
# Apache/1.3.31 (Unix)  (Gentoo/Linux) mod_bandwidth/2.0.4 mod_ssl/2.8.19 OpenSSL/0.9.7d PHP/4.3.11
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix):Apache/1\.3\.(29\|3[01]) .*\(Unix|[A-Za-z /]*Linux\):Apache/1.3.29-31 (Unix)
# Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 mod_throttle/3.1.2
# Apache/1.3.28 (Linux/SuSE) mod_python/2.7.10 Python/2.3+ PHP/4.3.3
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix) Resin/3.0.9 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.9 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7a
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-3]) \(Unix|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/1.3.27-33 (Unix)
# Apache/1.3.29 Ben-SSL/1.53
# Apache/1.3.27 OpenSSL/0.9.6 (Unix)
# Apache/1.3.33 (Darwin) PHP/5.0.1 DAV/1.0.3
# Apache/1.3.33 (Unix) DAV/1.0.3 mod_perl/1.29
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-3]):Apache/1.3.27-33 (Unix)
+++:HTM:403:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) mod_deflate/1.0.21 mod_accel/1.0.31 mod_ssl/2.8.19 OpenSSL/0.9.7d
+++:HTM:200:200:400:501:200:HTM:HTM:302:302:400:302:405:302:200:302:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) FrontPage/5.0.2.2623 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.3.3 mod_perl/1.26
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:405:405:405:200:405:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)
+++:HTM:200:200:400:501:403:HTM:HTM:200:301:400:200:405:200:200:200:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.27 (Unix) mod_throttle/3.1.2 PHP/4.3.2 FrontPage/5.0.2.2623 mod_ssl/2.8.14 OpenSSL/0.9.6b
# Apache/1.3.29 (Unix) PHP/4.3.8 mod_ssl/2.8.16 OpenSSL/0.9.6m
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.6b
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-16
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[79]|3[0-3]) \(Unix|[A-Za-z /]*Linux\):Apache/1.3.27-33 (Unix)
# Server's Module Magic Number: 19990320:15
# Compiled-in modules: http_core.c mod_charset.c mod_bandwidth.c mod_env.c mod_log_config.c mod_mime.c mod_negotiation.c mod_status.c
# mod_include.c mod_autoindex.c mod_dir.c mod_cgi.c mod_asis.c mod_imap.c mod_actions.c mod_userdir.c mod_alias.c mod_rewrite.c
# mod_access.c mod_auth.c mod_proxy.c mod_expires.c mod_headers.c mod_so.c mod_setenvif.c mod_ssl.c
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) FrontPage/5.0.2.2623 mod_ssl/2.8.16 OpenSSL/0.9.7c rus/PL30.18
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7d mod_fastcgi/2.4.2 Resin/2.1.12 PHP/4.3.8
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c mod_fastcgi/2.4.2 Resin/2.1.12 PHP/4.3.5RC2
+++:400:400:200:400:400:200:400:400:400:400:200:411:411:403:403:403:403:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix)
+++:HTM:403:200:400:302:302:HTM:HTM:302:302:400:200:405:200:200:200:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) FrontPage/5.0.2.2623
+++:HTM:403:200:400:403:301:HTM:HTM:400:400:400:200:403:403:200:403:403:301:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_jk/1.2.5
# Apache/1.3.28 Ben-SSL/1.52 (Unix) PHP/4.3.4
# Apache/1.3.29
# Apache/1.3.31 (Unix) PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7c-p1
# Apache/1.3.27 OpenSSL/0.9.6 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.32 (Unix) PHP/4.3.9 mod_ssl/2.8.21 OpenSSL/0.9.7d
# Apache/1.3.33 (Unix) PHP/5.0.3
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):^Apache(/1\.3\.(2[7-9]|3[0-3]).*)?$:Apache/1.3.27-33 (Unix)
# Apache/1.3.26 + PHP under Debian 3.0
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:403:403:200:403:200:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
+++:HTM:403:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
+++:HTM:200:200:400:400:200:HTM:HTM:400:200:400:200:200:200:200:200:200:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Linux/SuSE) mod_ssl/2.8.10 OpenSSL/0.9.6g mod_perl/1.27 mod_gzip/1.3.19.1a
# Apache/1.3.4 (Unix)
# Apache/1.3.6 (Unix)
# Apache/1.3.9 (Unix)
# Apache/1.3.9 (Unix) mod_perl/1.21
# Apache/1.3.9 (Unix)  (SuSE/Linux)
# Apache/1.3.12 (Unix)
# Apache/1.3.12 (Unix)  (SuSE/Linux)
# Apache/1.3.12 (Unix) mod_perl/1.24 ApacheJserv/1.1.2
# Apache/1.3.12 (Unix)  (Red Hat/Linux) PHP/3.0.15
# Apache/1.3.14 (Unix)  (Red-Hat/Linux) PHP/4.1.2 ApacheJServ/1.1.2
# Apache/1.3.14 (Unix)  (Red-Hat/Linux) PHP/3.0.18 mod_perl/1.23
# Apache/1.3.19 (Unix)
# Apache/1.3.20 (Unix)
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) PHP/4.1.2
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.0.6 mod_perl/1.26
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6d
# Apache/1.3.22 (Unix) PHP/4.3.2
# Apache/1.3.23 (Unix)  (Red-Hat/Linux)
# Apache/1.3.23 (Unix) PHP/4.1.2
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.24 (Unix) mod_jk
# Apache/1.3.24 (Unix)
# Oracle9iAS/9.0.2 Oracle HTTP Server
# Oracle9iAS/9.0.2.2.0 Oracle HTTP Server
# Oracle9iAS/9.0.3.1 Oracle HTTP Server
# Oracle HTTP Server Powered by Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_perl/1.24
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_plsql/3.0.9.8.3b mod_ssl/2.8.1 OpenSSL/0.9.5a mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_plsql/3.0.9.8.3c mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# MS-IIS/4.0-3  (WNT)	[is this a fake?]
##HTM:200:200:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++:^(Apache(/1\.3.(9|1[249]|2[0234])[^0-9].*)?|Oracle9iAS/9\.0\.[23].*|Oracle HTTP Server Powered by Apache/1\.3\.1[29].*)$:Apache/1.3.9 to 1.3.24
## Same as above but more precise ##
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER
# IBM_HTTP_Server/1.3.12.3 Apache/1.3.12 (Unix)
# IBM_HTTP_Server/1.3.12.4 Apache/1.3.12 (Unix)
# IBM_HTTP_Server/1.3.12.6 Apache/1.3.12 (Unix)
# IBM_HTTP_SERVER/1.3.19.1  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.4  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache/1.3.22 (Unix) PHP/4.0.6 mod_perl/1.26 FrontPage/5.0.2.2623 AuthMySQL/2.20 mod_ssl/2.8.5 OpenSSL/0.9.6a
# Apache/1.3.12 (Unix) PHP/4.3.1 rus/PL29.4
# Apache/1.3.12 (Unix) ApacheJServ/1.1 mod_perl/1.22
# TBD: verify Apache/1.3.7-dev & Apache/1.3.12
# IBM_HTTP_Server/1.3.6.1 Apache/1.3.7-dev (Unix)
# IBM_HTTP_Server/1.3.6.1 Apache/1.3.7-dev (Unix) PHP/4.0.6
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Unix)
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Unix) PHP/4.0.4
# Apache/1.3.19 (Unix) Resin/1.2.2 mod_ssl/2.8.3 OpenSSL/0.9.6a
# Oracle HTTP Server Powered by Apache/1.3.19 (Unix) mod_fastcgi/2.2.10 mod_perl/1.25 mod_oprocmgr/1.0
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
# Oracle9iAS/9.0.2 Oracle HTTP Server
# Apache/1.3.12p (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):^(IBM_HTTP_SERVER$|Oracle9iAS/9\.0\.2[0-9.]* Oracle HTTP Server|(Oracle HTTP Server Powered by +|IBM_HTTP_SERVER/1\.3\.1?[0-9](\.[0-9])? +)?Apache/1\.3\.(1[2-9]|2[0-2])[a-z]? \(Unix\)):Apache/1.3.12-22 (Unix) [may be IBM_HTTP_SERVER/1.3.x or Oracle HTTP Server]
# Oracle9iAS/9.0.2.1.0 Oracle HTTP
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix) PHP/4.2.2
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Unix)
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_watch/3.17 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.19 Ben-SSL/1.44 (Unix) PHP/4.0.3pl1
# Apache/1.3.24 Ben-SSL/1.48 (Unix) PHP/3.0.18
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_jk/1.2.0 mod_perl/1.24_01 PHP/4.1.1 FrontPage/5.0.2 mod_ssl/2.8.5 OpenSSL/0.9.6b
# Apache/1.3.12 (Unix) PHP/4.0.4pl1
# Apache/1.3.12 (Unix) PHP/3.0.15
# Apache/1.3.17 (Unix) PHP/4.3.1
# Apache/1.3.19 (Unix) Resin/2.1.0
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^(Oracle9iAS/9\.0\.2|(IBM_HTTP_SERVER/1\.3\.19(\.[2-5])? )?Apache(-AdvancedExtranetServer)?/1\.3\.(1[2-9]|2[0-4]) [A-Za-z ]*\(Unix|Mandrake Linux/4mdk|Red-Hat/Linux\)):Apache/1.3.12-24 (Unix) [might be IBM_HTTP_SERVER/1.3.19.x] -or- Oracle9iAS/9.0.2.x
# Slightly different
+++:xxx:200:200:200:501:200:HTM:xxx:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::IBM_HTTP_SERVER/1.3.19.2  Apache/1.3.20 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:---:200:404:501:403:+++:Apache/1.3 (Unix)::IBM_HTTP_SERVER/1.3.19.5  Apache/1.3.20 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_perl/1.26
##HTM:200:403:200:200:200:HTM:501:200:200:HTM:HTM:200:400:400:+++:400:404:405:404:200:200:404:501:+++:Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk)
# More precise!
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3(Netware)::Apache/1.3.20a (NETWARE) mod_jk
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4mdk) PHP/4.1.2
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.4 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_perl/1.25
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache(-AdvancedExtranetServer)?/1\.3\.2[0-3]:Apache/1.3.20-23 (Unix)
# Apache-AdvancedExtranetServer/1.3.23 (Mandrake Linux/4.2mdk) mod_ssl/2.8.7 OpenSSL/0.9.6c PHP/4.1.2
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6.3.90mdk) DAV/1.0.3 PHP/4.2.3
# Apache-AdvancedExtranetServer/1.3.26 (Mandrake Linux/6mdk) sxnet/1.2.4 mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.3
+++:HTM:403:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache(-AdvancedExtranetServer)?/1\.3\.2[3-6]:Apache/1.3.23-26 (Linux)
# Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk)
# Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk) mod_fastcgi/2.4.0 sxnet/1.2.4 mod_ssl/2.8.15 OpenSSL/0.9.7b PHP/4.3.3
# Apache/1.3.29 (Debian GNU/Linux) PHP/4.3.3 mod_ssl/2.8.14 OpenSSL/0.9.7b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.27  (Unix) (Red-Hat/Linux) mod_watch/3.12 mod_throttle/3.1.2  mod_gzip/1.3.19.1a mod_auth_pam/1.0a mod_ssl/2.8.11 OpenSSL/0.9.6j  PHP/4.3.3 mod_perl/1.26 FrontPage/5.0.2.2510
# Apache/1.3.27 (Unix)   [on QNX without mod_fastcgi]
# Apache/1.3.27 (Unix) Debian GNU/Linux [on Xandros]
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Unix)
# Apache/1.3.31 (Unix) PHP/4.3.6
# Apache/1.3.31 (Unix) mod_perl/1.29 [mod_auth_external, mod_perl and HTML::Mason on Slackware Linux 9.1]
# Apache/1.3.32 (Unix) mod_jk/1.2.6 mod_mono/1.0.1 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.9 FrontPage/5.0.2.2634a mod_ssl/2.8.21 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix) mod_perl/1.29
# Apache/1.3.33 (Unix) Resin/3.0.9 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2634a mod_ssl/2.8.22 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.36 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.2 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.27 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) PHP/4.4.4
# Apache/1.3.37 (Unix) mod_fastcgi/2.4.2 PHP/4.3.10
# Apache/1.3.37 (Unix) PHP/4.4.4
# Apache/1.3.37 (Unix) mod_gzip/1.3.19.1a PHP/4.4.4 mod_ssl/2.8.28 OpenSSL/0.9.6m
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7f PHP-CGI/0.1b
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):(IBM_HTTP_SERVER|Apache(-AdvancedExtranetServer)?)/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-37 (Unix)
+++:HTM:200:200:400:301:301:HTM:HTM:400:400:400:404:405:404:200:404:501:301:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/5.1.1 mod_perl/1.29
# Apache/1.3.31 (Unix) mod_ssl/2.8.18 OpenSSL/0.9.7d mod_gzip/1.3.26.1a mod_security/1.5 PHP/4.3.8
# Apache/1.3.33 (Darwin) PHP/4.3.10
# Apache/1.3.33 (Darwin) PHP/4.4.4
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:403:+++:Apache/1.3 (Unix):Apache/1\.3\.3[1-3] \(Unix|Darwin|Linux\) .*PHP/4\.[34]:Apache/1.3.31-33 (Unix) PHP/4.3-4.4
+++:---:200:200:400:501:200:---:---:400:400:---:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix)::Apache-AdvancedExtranetServer/1.3.28 (Mandrake Linux/3.1.92mdk) mod_fastcgi/2.2.12 sxnet/1.2.4 mod_ssl/2.8.15 OpenSSL/0.9.7b PHP/4.3.3
+++:HTM:200:200:400:501:200:HTM:HTM:400:+++:+++:404:405:404:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Red-Hat/Linux)
+++:HTM:501:200:400:400:---:HTM:---:400:400:400:404:405:404:501:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) dynamicScale/2.0.3 PHP/4.3.3
+++:HTM:501:200:400:400:200:HTM:HTM:400:400:400:404:405:404:501:501:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26
# Apache on Debian GNU/Linux
+++:HTM:200:200:400:200:200:HTM:HTM:400:+++:+++:404:405:404:200:404:501:400:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) Debian GNU/Linux
# More precise
# Apache/1.3.28 (Unix) Resin/2.1.8 PHP/4.3.2 mod_ssl/2.8.15 OpenSSL/0.9.7b
# Apache/1.3.28 Ben-SSL/1.49 (Unix) Resin/2.1.13
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:400:+++:Apache/1.3 (Unix):^Apache/1\.3\.28 .*\(Unix\):Apache/1.3.28 (Unix)
+++:HTM:200:200:---:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) Debian GNU/Linux
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
# An older signature also matched Apache/1.3.27 (Unix) Debian GNU/Linux
# Apache/1.3.29 (Unix) PHP/4.3.4
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.2 mod_perl/1.24_01
# Apache/1.3.28 (Linux/SuSE) mod_perl/1.28
# Apache/1.3.31 Ben-SSL/1.53 (Unix)
# Apache/1.3.34 (Unix)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-4]) \(Unix|Linux/SuSE|[A-Z ]*Linux[a-z0-9 /]*):Apache/1.3.27-34 (Unix)
+++:xxx:403:200:400:501:200:HTM:xxx:400:+++:+++:404:405:404:403:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.28 (FreeBSD/locked)
+++:HTM:200:200:400:501:200:HTM:HTM:400:301:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) mod_deflate/1.0.19 mod_accel/1.0.30
+++:HTM:200:200:400:501:200:---:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.2 PHP/4.3.3 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6b
+++:HTM:200:200:400:501:200:HTM:HTM:404:301:400:404:403:403:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6k
+++:HTM:200:200:400:500:500:HTM:HTM:404:301:400:VER:405:VER:200:VER:501:500:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix)
+++:HTM:200:200:400:501:200:HTM:HTM:404:301:400:VER:405:VER:200:VER:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix)
# Apache/1.3.29 (Unix) PHP/4.3.4 mod_throttle/3.1.2 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.31 (Debian GNU/Linux) mod_gzip/1.3.26.1a PHP/4.3.9-1 mod_ssl/2.8.19 OpenSSL/0.9.7d mod_perl/1.29
# Apache/1.3.32 (Unix) PHP/4.3.4 mod_throttle/3.1.2 mod_ssl/2.8.21 OpenSSL/0.9.7e
+++:HTM:403:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(29|3[0-2]) \(Unix|[A-Za-z /]*Linux\):Apache/1.3.29-32 (Unix)
# Raw sig: httpd-2.0.46-25.ent + openssl-0.9.7a-33.12 on Red Hat Enterprise Linux ES release 3 (Taroon)
+++:HTM:200:401:400:401:401:HTM:HTM:400:400:400:401:401:401:200:401:401:401:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c [possibly on Red Hat Enterprise Linux ES release 3?]
+++:HTM:200:200:400:500:500:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) FrontPage/5.0.2.2635 mod_ssl/2.8.17 OpenSSL/0.9.7c
+++:HTM:400:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) mod_fastcgi/2.4.2 FrontPage/5.0.2.2635 mod_jk/1.2.5
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:302:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.6b
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Debian GNU/Linux)
# Apache/1.3.29 (Unix) ApacheJServ/1.1.2 PHP/4.3.4 mod_throttle/2.11 FrontPage/5.0.2.2634 Rewrit/1.1a
# Apache/1.3.31 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.8 FrontPage/5.0.2.2634a mod_ssl/2.8.19 OpenSSL/0.9.7a
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(29|3[01]) \(Unix\):Apache/1.3.29-31 (Unix)
# Apache/1.3.29 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.4 FrontPage/5.0.2.2634 mod_ssl/2.8.16 OpenSSL/0.9.6b
# Apache/1.3.29 (Unix)  (PLD/Linux) mod_ssl/2.8.15 OpenSSL/0.9.6j mod_fastcgi/2.2.12 PHP/4.2.3 mod_perl/1.27
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.4
# Apache/1.3.28 (Unix) PHP/4.3.3
# Apache/1.3.31 (Unix) Mya/1.2 PHP/4.3.8 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.27 (Unix) PHP/4.2.3
# Apache/1.3.27 (Unix) PHP/4.2.2 [xxx -> htm]
# Apache/1.3.27 (ALT Linux/alt13) PHP/4.3.1-dev/ALT rus/PL30.16
# Apache/1.3.29 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.2.3 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.32 (Unix) mod_gzip/1.3.19.1a PHP/4.3.9 mod_ssl/2.8.21 OpenSSL/0.9.6m
# Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7a
# Apache/1.3.34 (Debian) PHP/4.4.0-4 mod_perl/1.29
# Apache/1.3.34 (Debian) PHP/4.4.4-8 mod_perl/1.29
# Apache/1.3.34 (Debian) PHP/4.4.2-1.1
# Apache/1.3.34 (Debian) PHP/5.1.6-3
# Apache/1.3.34 (Debian) PHP/5.1.6-5 mod_ssl/2.8.25 OpenSSL/0.9.8c
# Apache/1.3.34 (Unix) mod_choke/0.06 mod_throttle/3.1.2 PHP/4.4.1
# Apache/1.3.37 (Unix) DAV/1.0.3 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.11 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7d mod_python/2.7.11 Python/2.4
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-7]) [a-zA-Z ]*\(Unix|[A-Za-z/ ]*Linux[A-Za-z0-9/ ]*|Debian\):Apache/1.3.27-37 (Unix) [PHP/4?]
# Apache/1.3.27 (Unix) Resin/2.1.6 mod_throttle/3.1.2
# Apache/1.3.27 (Unix) PHP/4.2.2
# Apache/1.3.28 (Unix) Resin/2.1.10 mod_throttle/3.1.2 mod_ssl/2.8.15 OpenSSL/0.9.7a
# Apache/1.3.31 (Unix) PHP/4.3.11
# Apache/1.3.33 (Unix) PHP/4.3.11
+++:xxx:200:200:400:200:200:xxx:xxx:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[7-9]|3[0-3]) \(Unix\): Apache/1.3.27-33 (Unix)
# Although cover the previous case (should be improved)
+++:HTM:200:200:400:200:200:HTM:HTM:400:+++:+++:404:405:404:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.28
# More precise
# Apache/1.3.27 (Unix) PHP/4.3.2 mod_webapp/1.2.0-dev
# Apache/1.3.36 (Unix) PHP/5.1.4
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:---:+++:Apache/1.3 (Unix):Apache/(1\.3\.2[7-9]|3[0-6]) \(Unix\):Apache/1.3.27-36 (Unix) w/ PHP
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:302:302:200:302:302:200:+++:Apache/1.3 (Unix)::Apache/1.3.33 (ALT Linux/alt1) PHP/4.3.10-ALT
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.9 (Unix) DAV/0.9.16 AuthMySQL/2.20 PHP/3.0.12 mod_perl/1.21 mod_ssl/2.4.5 OpenSSL/0.9.4
# Apache 1.3.9 on Linux 2.2.16 (gcc version 2.7.2.3)
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:404:405:404:403:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.9 (Unix) PHP/4.2.3 PHP/3.0.18
# Linux 2.2.19-6.2.1 (RedHat 6.2) Apache 1.3.29 modssl 2.8.16 openssl 0.9.7c
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:405:200:403:200:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (RedHat 6.2) modssl/2.8.16 OpenSSL/0.9.7c
+++:HTM:403:200:400:HTM:HTM:HTM:HTM:500:500:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix)
# Apache/1.3.29 (Unix) PHP/4.3.4 mod_perl/1.29
# Apache/1.3.28 (Unix) PHP/4.3.3 mod_ssl/2.8.15 OpenSSL/0.9.7b
# Apache/1.3.4 (Unix)
# Apache/1.3.29 (Unix)  (PLD/Linux) mod_fastcgi/2.2.12 PHP/4.2.3
# Apache/1.3.29 (Unix) mod_perl/1.29 PHP/4.3.4 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.31 (Unix) Midgard/1.5.0/SG PHP/4.3.9
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Unix):^Apache/1\.3\.(4|2[89]|3[01]) \(Unix\):Apache/1.3.4-31 (Unix)
# More precise
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:400:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) Resin/2.1.10 mod_ssl/2.8.14 OpenSSL/0.9.7b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_jk/1.2.0 mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux)
# More precise
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:HTM:Apache/1.3 (Unix)::Apache/1.3.42 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 mod_gzip/1.3.26.1a FrontPage/5.0.2.2635 mod_ssl/2.8.31 OpenSSL/0.9.8e-fips-rhel5
# Apache/1.3.29 (Unix) mod_perl/1.29 PHP/4.3.4 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.29 (Unix) PHP/4.3.2
+++:HTM:200:403:400:501:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.29 \(Unix\) .*PHP/4\.3\.[2-4]:Apache/1.3.29 (Unix) PHP/4.3.2-4
+++:HTM:200:302:200:501:200:HTM:HTM:400:+++:400:404:403:403:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.11 (Unix) mod_perl/1.21 AuthMySQL/2.20
# Apache/1.3.11 (Unix) mod_fastcgi/2.2.2 ApacheJServ/1.1 FrontPage/4.0.4.3 mod_perl/1.21
# IBM_HTTP_SERVER/1.3.19.1  Apache/1.3.20 (Unix)
# Apache/1.3.19 (Unix) FrontPage/5.0.2.2510
# Apache/1.3.6 (Unix) mod_ssl/2.3.5 OpenSSL/0.9.3a
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.([6-9]|1[1-9](\.[0-9]+)?) \(Unix\):Apache/1.3.6-19 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.19 (Unix) PHP/4.3.4 mod_gzip/1.3.19.1a Resin/2.1.0
# Apache/1.3.19 (Unix)  (SuSE/Linux) PHP/4.1.2 mod_perl/1.25 mod_throttle/3.0 mod_layout/1.0 mod_fastcgi/2.2.2 mod_dtcl
# Apache/1.3.12 (Unix) PHP/4.3.0
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.1[2-9] \(Unix\):Apache/1.3.12-19 (Unix)
+++:HTM:500:500:500:500:HTM:HTM:HTM:500:500:500:200:500:500:500:500:500:500:+++:Apache/1.3 (Unix)::IBM_HTTP_Server/1.3.12.2 Apache/1.3.12 (Unix)
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.12 (Unix) PHP/4.2.1 FrontPage/4.0.4.3
#### The same server returns two different signatures
+++:---:200:200:400:200:200:---:---:400:301:400:404:405:404:200:403:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) Debian GNU/Linux mod_ssl/2.8.14 OpenSSL/0.9.7b Midgard/1.5.0/SG PHP/4.2.3
+++:---:200:200:400:200:200:---:---:400:301:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) Debian GNU/Linux mod_ssl/2.8.14 OpenSSL/0.9.7b Midgard/1.5.0/SG PHP/4.2.3
####
# Unreliable signature
+++:xxx:405:301:400:405:400:xxx:xxx:400:400:400:405:405:405:200:405:405:400:+++:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) mod_forward_0_3 [aka reverse proxy]
# Cobalt
+++:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:404:200:501:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.1pl2 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.3pl1 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.1.2 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.3 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.4 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.2.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.2 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b (Webkun Logging) WEBKUN(tm)/1.1 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6g PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_auth_pam_external/0.1 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.2.3 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.3 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_throttle/3.1.2 PHP/3.0.18-i18n-ja mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) PHP/4.3.0 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.6 (Unix) mod_perl/1.21 mod_ssl/2.2.8 OpenSSL/0.9.2b
# Apache/1.3.20 Sun Cobalt
+++:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:+++:Apache/1.3 (Unix):^Apache/1\.3\.(6|12|20) ((Sun )?Cobalt|\(Unix\)):Apache/1.3.6-20 [might Sun Cobalt]
# Apache/1.3.29 Sun Cobalt
# Apache/1.3.27 (Unix) PHP/4.1.2 mod_perl/1.27 mod_auth_pam/1.1.1 mod_ssl/2.8.12 OpenSSL/0.9.7
+++:HTM:200:200:400:302:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:+++:Apache/1.3 (Unix):^Apache/1\.3\.2[7-9] (Sun Cobalt|\(Unix\)):Apache/1.3.27-29 (Unix)
+++:HTM:200:200:400:302:302:HTM:HTM:400:400:400:404:403:403:200:404:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.29 Sun Cobalt (Unix) mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.0.6 mod_auth_pam_external/0.1 mod_jk/1.1.0 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.12 Cobalt (Unix) mod_ssl/2.6.4 OpenSSL/0.9.5a PHP/4.0.3pl1 mod_auth_pam/1.0a FrontPage/4.0.4.3 mod_perl/1.24
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.3pl1 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 mod_jk/1.1.0 FrontPage/4.0.4.3 mod_perl/1.25
+++:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:403:403:200:404:501:302:+++:Apache/1.3 (unix)::Apache/1.3.20 Sun Cobalt (Unix)
+++:HTM:403:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (unix)::Apache/1.3.20 Sun Cobalt (Unix) PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_ssl/2.8.4 OpenSSL/0.9.6b mod_perl/1.25
+++:HTM:200:200:302:302:302:HTM:HTM:400:400:400:302:405:302:200:302:501:302:+++:Apache/1.3 (unix)::Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
+++:HTM:200:200:302:302:302:HTM:HTM:400:400:400:200:200:200:200:200:200:302:+++:Apache/1.3 (unix)::Apache/1.3.20 Sun Cobalt (Unix) mod_watch/3.14 mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Nokia IP350 Check Point NG
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.6 (Unix) mod_auth_pam/1.0a mod_ssl/2.3.11 OpenSSL/0.9.5a
# Apache/1.3.27 (Darwin) tomcat/1.0 mod_ssl/2.8.13 OpenSSL/0.9.6i
+++:HTM:200:200:400:501:---:---:---:400:+++:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Darwin)
+++:HTM:200:200:400:501:---:---:---:400:+++:400:404:401:401:200:401:405:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Darwin) DAV/1.0.3
+++:HTM:200:200:400:501:200:HTM:HTM:400:+++:400:404:401:401:200:401:405:+++:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Darwin) DAV/1.0.3
# Apache/1.3.29 (Darwin) PHP/4.3.2 DAV/1.0.3
# Apache/1.3.33 (Darwin) PHP/5.0.4 mod_jk/1.2.6 mod_ssl/2.8.24 OpenSSL/0.9.7i PHP/4.4.1
+++:HTM:200:200:400:200:---:---:---:400:400:400:404:405:404:403:404:501:---:+++:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-3]) \(Darwin\):Apache/1.3.29-33 (Darwin)
+++:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) FrontPage/5.0.2.2510 mod_gzip/1.3.19.1a
# Apache/1.3.29 (Unix) mod_gzip/1.3.26.1a mod_ssl/2.8.16 OpenSSL/0.9.7c mod_jk/1.2.5
# Apache/1.3.28 (Darwin)
# IBM_HTTP_SERVER
# Apache/1.3.29 (Darwin) PHP/4.3.2
# Apache/1.3.33 (Darwin) PHP/5.0.4
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:403:404:501:403:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[89]|3[0-3]):Apache/1.3.28-33 (Unix)
# Novell 6 server running Apache Tomcat 3.2.2 and 3.3 with Novell JVM 1.3.0_02.
+++:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Netware)::Apache/1.3.27 (NETWARE) mod_jk/1.2.2-dev
# Same as above but more precise
# Apache/1.3.27-29 (NETWARE) mod_jk/1.2.2-dev
# Apache/1.3.28 (Unix) mod_ssl/2.8.15 OpenSSL/0.9.7c
+++:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Netware) or Apache/1.3 (Unix):^Apache/1\.3\.2[789] \(NETWARE|Unix\):Apache/1.3.27-29 (Netware/Unix)
# Also more precise
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7c PHP/4.3.3
# Apache/1.3.33 (Unix) OpenSSL/0.9.6m PHP/4.3.11
+++:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix):^Apache/1\.3\.(2[789]|3[0-3]) \(Unix\):Apache/1.3.27-33 (Unix) [w/ PHP 4.3]
#
# suspicious signature
# Apache/2.0.54 (Gentoo/Linux) PHP/4.4.0
# Apache/2.0.55 (Unix)
# Apache/2.0.59 (Unix) PHP/4.4.4
+++:---:200:200:200:200:200:---:---:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix):Apache/2\.0\.5[4-9] \(([A-Za-z /]*Linux|Unix)\):Apache/2.0.55-59 (Unix)
# Conflicting & more precise signature
# Apache/2.0.48 (Linux/SuSE)
# Apache/2\.2:Apache/2.2.3 (Ubuntu) PHP/5.2.1 mod_ssl/2.2.3 OpenSSL/0.9.8c
---:---:200:200:200:200:200:---:---:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.(4[8-9]|5[0-9])|2\.[0-3]) \(([A-Za-z /]*Linux[A-Za-z /]*|Ubuntu)\):Apache/2.0.48-2.2.3 (Linux)
# Apache/2.2.3 (CentOS)
# Apache/2.0.52 (CentOS) mod_perl/1.99_16 Perl/v5.8.5 DAV/2 PHP/4.3.9 mod_python/3.1.3 Python/2.3.4 mod_ssl/2.0.52 OpenSSL/0.9.7a [unconfigured]
+++:HTM:200:403:403:501:403:HTM:HTM:400:400:400:404:405:405:200:405:405:403:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[0-9]|2\.[0-3]) \(CentOS\):Apache/2.0.52-2.2.3 (CentOS)
+++:HTM:403:403:403:403:403:HTM:HTM:400:400:400:403:403:403:403:403:403:403:+++:::Apache/2 w/ mod_dosevasive
# More precise & conflicting
HTM:HTM:403:403:403:403:403:HTM:HTM:400:400:400:403:403:403:403:403:403:403:403:Apache/2.0 (Unix)::Apache/2.2.3 (CentOS)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:403:+++:Apache/2.0 (Unix)::Apache/2.0.39 (Unix) DAV/2
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.44 (Unix) PHP/4.3.1
# Apache/2.0.44 (Unix) PHP/4.3.0
# Apache2 on Linux Gentoo (2.0.46, 2.0.47, 2.0.47-r1, 2.0.48-r1, 2.0.48, 2.0.49-r1)
# Apache-AdvancedExtranetServer/2.0.50 (Mandrakelinux/5mdk) mod_ssl/2.0.50 OpenSSL/0.9.7d PHP/4.3.8
# Apache/2.0.53 (FreeBSD) PHP/4.3.10
# Apache/2.0.58 (Gentoo)
# Apache/2.0.59 (FreeBSD) PHP/4.4.4 with Suhosin-Patch
# Apache/2.2.0 (Unix) PHP/5.1.1
# Apache/2.2.3 (Unix) mod_mono/1.2.1
# Apache/2.2.3 (Debian) PHP/4.4.4-8 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.3 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache(-AdvancedExtranetServer)?/2\.(0\.(4[0-9]|5[0-9])|2\.[0-3]) \([A-Za-z /]*Linux[A-Za-z /]*|FreeBSD|Debian|Unix\):Apache/2.0.40-2.2.3 (Unix)
# Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/6mdk) mod_ssl/2.0.48 OpenSSL/0.9.7c DAV/2 PHP/4.3.4
# Apache/2.0.40 (Red Hat Linux)
# IBM_HTTP_Server/2.0.42 2.0.42 (Unix) DAV/2
# IBM_HTTP_Server/2.0.42.2 Apache/2.0.46 (Unix) DAV/2
# Apache/2.0.48 (Unix) DAV/2
# Apache/2.0.48 (Fedora)
# Apache/2.0.50 (Trustix Secure Linux/Linux) mod_ssl/2.0.50 OpenSSL/0.9.7c DAV/2 PHP/5.0.0-dev
# Apache/2.0.46 (Red Hat)
# Apache/2.0.51 (Fedora)
# Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/6.6.100mdk) mod_perl/1.99_11 Perl/v5.8.3 mod_ssl/2.0.48 OpenSSL/0.9.7c DAV/2 PHP/4.3.4
# Apache/2.0.52 (Unix) DAV/2 Resin/3.0.9
# Apache/2.0.52 (CentOS)
# Apache-AdvancedExtranetServer/2.0.53 (Mandrakelinux/PREFORK-9mdk) mod_auth_external/2.2.9 mod_ssl/2.0.53 OpenSSL/0.9.7d DAV/2 PHP/4.3.10 mod_perl/1.999.21 Perl/v5.8.6
# Apache/2.0.54 (Unix) mod_ssl/2.0.54 OpenSSL/0.9.6g DAV/2 PHP/5.0.4 SVN/1.3.1
# Apache/2.0.54 (Debian GNU/Linux) mod_ssl/2.0.54 OpenSSL/0.9.7e DAV/2 mod_apreq2-20051231/2.5.7 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.0.54 (Fedora)
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 SVN/1.1.4 mod_ssl/2.0.54 OpenSSL/0.9.7e
# Apache/2.0.55 (Unix) DAV/2 PHP/5.0.4 mod_perl/2.0.1 Perl/v5.8.4
# Apache/2.0.55 (Unix) DAV/2 mod_ssl/2.0.55 OpenSSL/0.9.8c PHP/5.1.1
# Apache/2.0.55 (Ubuntu) DAV/2
# Apache/2.0.55 (Ubuntu) DAV/2 SVN/1.3.1 PHP/5.1.2
# Apache/2.0.55 (Ubuntu) DAV/2 SVN/1.3.2 PHP/5.1.6
# Apache/2.0.55 (Debian) DAV/2 SVN/1.2.3 PHP/4.4.2-1+b1 mod_ssl/2.0.55 OpenSSL/0.9.8a
# Apache/2.2.2 (iTools 8.2.2)/Mac OS X) mod_ssl/2.2.2OpenSSL/0.9.7i DAV/2 mod_fastcgi/2.4.2 PHP/5.1.5
# Apache/2.2.0 (FreeBSD) mod_ssl/2.2.0 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.1.2
# Apache/2.2.3 (Gentoo) DAV/2 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.3 (Debian) DAV/2 PHP/4.4.4-8
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/5.2.0-3 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.0 mod_jk/1.2.18 mod_python/3.2.10 Python/2.4.4c0
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-7 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.3 (Debian) DAV/2 PHP/5.2.0-7 mod_ssl/2.2.3 OpenSSL/0.9.8c mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/5.2.0-7 mod_ruby/1.2.6 Ruby/1.8.5(2006-08-25) mod_ssl/2.2.3 OpenSSL/0.9.8c mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 mod_python/3.2.10 Python/2.4.4 PHP/5.2.0-7 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.3 (Debian) mod_auth_pgsql/2.0.3 DAV/2 SVN/1.4.0 PHP/4.4.4-2 mod_ssl/2.2.3 OpenSSL/0.9.8c mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.4 (Gentoo) DAV/2 mod_ssl/2.2.4 OpenSSL/0.9.8d
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^(Apache(-AdvancedExtranetServer)?|IBM_HTTP_Server)/2\.(0\.(4[0-9]|5[0-9])|2\.[0-4]) \([a-zA-Z /]*(Unix|[lL]inux|Fedora|Debian|CentOS|Red Hat|Gentoo|Ubuntu|.*Mac OS X|FreeBSD)[a-zA-Z0-9/-]*\):Apache/2.0.40-2.2.4 (Unix)
# Apache/2.2.24 (FreeBSD) mod_ssl/2.2.24 OpenSSL/0.9.8y DAV/2
---:---:---:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:405:200:403::^Apache/2\.2\.24 \(FreeBSD:Apache/2.2.24 (FreeBSD)
# Apache/2.2.11 (Unix) -- on Mac OS X Server 10.6
# Apache/2.2.17 (Unix) -- on Mac OS X Server 10.6.8
# Apache/2.2.21 (Unix) -- on Mac OS X Server 10.6.8 (with Security Update 2012-001)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:405:405:501:200:403:Apache/2.2 (Unix):Apache/2\.2\.(11|17|21):Apache/2.2.11-21 (Unix) on Mac OS X Server
# Apache/2.0.48 (Unix) mod_ssl/2.0.48 OpenSSL/0.9.7d PHP/4.3.5 mod_python/3.1.2b Python/2.3.3
# Apache 2 on Debian GNU/Linux 3.0r2 with:
# core mod_access mod_auth mod_include mod_log_config mod_env mod_expires
# mod_unique_id mod_setenvif mod_ssl prefork http_core mod_mime mod_status
# mod_autoindex mod_asis mod_cgi mod_negotiation mod_dir mod_imap
# mod_actions mod_userdir mod_alias mod_rewrite mod_so sapi_apache2
# mod_python
# Apache/2.0.49 (FreeBSD) PHP/4.3.7 mod_ssl/2.0.49 OpenSSL/0.9.7c-p1
# Apache/2.2.0 (Linux/SUSE)
# Apache/2.2.3 (Debian) [PHP/5.2.0-7]
+++:XML:200:200:200:200:200:XML:XML:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (unix) or Apache/2.2 (Unix):^Apache/2\.(0\.(4[89]|5[0-9])|2\.[0-3]) \(Unix|FreeBSD|Debian|Linux[/A-Za-z ]*\):Apache/2.0.48-2.2.3 (Unix)
# Apache/2.0.40 (Red Hat Linux) [httpd-2.0.40-21 on Redhat 9]
# Apache/2.0.46 (CentOS) [w/ PHP/5.0.4]
# Apache/2.0.47 (Fedora)
# Apache/2.0.48 (Fedora)
# Apache/2.0.51 (Unix) mod_ssl/2.0.51 OpenSSL/0.9.7d DAV/2 PHP/4.3.8
# Apache/2.0.52 (CentOS) [w/ PHP/4.3.9]
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 PHP/4.3.10-15
# Apache/2.0.55 (Debian)
# Apache/2.0.55 (Debian) DAV/2 PHP/4.4.2-1.1 mod_ssl/2.0.55 OpenSSL/0.9.8c mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.0.59 (FreeBSD) PHP/4.4.4 with Suhosin-Patch DAV/2 mod_ssl/2.0.59 OpenSSL/0.9.7d-p1
# Apache/2.2.0 (FreeBSD) mod_ssl/2.2.0
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/4.4.4-6 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/5.2.0-7 mod_perl/2.0.2 Perl/v5.8.8
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (unix) or Apache/2.2 (Unix):^Apache/2\.(2\.[0-9]|0\.(4[0-9]|5[0-9])) \(FreeBSD|Debian|Fedora|CentOS|[A-Za-z/ ]*Linux|Unix|RedHat[A-Za-z0-9 /]*\):Apache/2.0.40-2.2.0 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:400:405:501:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (Debian GNU/Linux) mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-16 mod_perl/1.999.21 Perl/v5.8.4
+++:HTM:200:200:200:404:200:404:HTM:404:404:400:404:404:404:200:404:404:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Unix)
# Server version: Apache/2.0.55
# Server built:   Aug 16 2007 22:27:29
# PHP 5.1.2 (cli) (built: Jul 17 2007 17:32:48)
# Zend Engine v2.1.0, Copyright (c) 1998-2006 Zend Technologies
# Linux 2.6.20.12 i686
# ubuntu 6.06 server.
HTM:HTM:401:401:401:401:401:HTM:HTM:400:400:400:401:401:401:403:401:401:401:401:Apache/2.0 (Unix)::Apache/2.0.55 (Ubuntu) PHP/5.1.2 mod_ssl/2.0.55 OpenSSL/0.9.8a
#
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:---:403:Apache/2.2 (Unix):Apache/2\.2\.4:Apache/2.2.4 (FreeBSD) mod_ssl/2.2.4 OpenSSL/0.9.7e-p1 DAV/2 [protected by Fortinet IPS]
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:---:403:Apache/2.0 (Unix):Apache/2\.0\.59:Apache/2.0.59 (FreeBSD) [protected by Fortinet IPS]
---:---:200:302:200:200:200:---:---:400:400:400:404:405:405:200:405:405:---:403:Apache/2.2 (Unix) + Suhosin:Apache/2\.2\.4:Apache/2.2.4 PHP/5.2.3 Suhosin
---:---:200:200:200:200:200:---:---:400:400:400:404:405:405:200:405:405:---:403:Apache/2.2 (Unix) + Suhosin:Apache/2\.2\.4:Apache/2.2.4 PHP/5.2.3 Suhosin
# Apache/2.0.48 (Unix) PHP/4.3.4
# Apache/2.0.45 (Unix) mod_ssl/2.0.45 OpenSSL/0.9.7a PHP/4.3.3
# Apache-AdvancedExtranetServer/2.0.47 (Mandrake Linux/6mdk) mod_perl/1.99_09 Perl/v5.8.1 mod_ssl/2.0.47 OpenSSL/0.9.7b PHP/4.3.2
# Apache/2.0.48 (Unix) PHP/4.3.4
# Apache/2.0.50 (Trustix Secure Linux/Linux) mod_jk2/2.0.2 PHP/4.3.8 mod_ssl/2.0.50 OpenSSL/0.9.7c
# Apache/2.0.50 (FreeBSD)
# Apache/2.0.53 (FreeBSD) PHP/4.3.10
# Apache/2.0.54 (Debian GNU/Linux) PHP/4.3.10-18
# Apache/2.0.55 (Ubuntu) PHP/5.1.2
# Apache/2.0.55 (Ubuntu) PHP/5.1.6 mod_ssl/2.0.55 OpenSSL/0.9.8b
# Apache/2.0.58 (FreeBSD) PHP/5.1.4
# Apache/2.0.59 (Unix) mod_ssl/2.0.59 OpenSSL/0.9.7g
# Apache/2.0.59 (FreeBSD) PHP/5.1.6 with Suhosin-Patch
# Apache/2.2.0 (Unix) PHP/4.4.2
# Apache/2.2.0 (Linux/SUSE)
# Apache/2.2.3 (Debian) PHP/5.2.0-7
# Apache/2.2.3 (Debian) mod_python/3.2.10 Python/2.4.4c0 PHP/4.4.4-6 mod_perl/2.0.2 Perl/v5.8.8
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache(-AdvancedExtranetServer)?/2\.(0\.(4[5-9]|5[0-9])|2\.[0-3]):Apache/2.0.45-2.2.3 (Unix) w/ PHP/4.3-5.2
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (FreeBSD) PHP/4.3.11
# Apache/2.0.48 (Fedora)
# Apache/2.0.49 (Debian GNU/Linux) mod_perl/1.99_12 Perl/v5.8.3 PHP/4.3.5 mod_ssl/2.0.49 OpenSSL/0.9.7d
# Apache/2.0.52 (Fedora)
# Apache/2.0.53 (Fedora)
# Apache/2.0.54 (Debian GNU/Linux) PHP/4.3.10-18 mod_ssl/2.0.54 OpenSSL/0.9.7e
# Apache/2.0.55 (FreeBSD) PHP/4.4.1 mod_fastcgi/2.4.2 DAV/2 SVN/1.3.1 mod_ssl/2.0.55 OpenSSL/0.9.7e-p1 mod_perl/2.0.2 Perl/v5.8.8
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:+++:Apache/2.0 (Unix):^Apache/2\.0\.(4[89]|5[0-5]):Apache/2.0.48-55 (Unix)
# Apache/2.0.49 (Trustix Secure Linux/Linux) [Trustix 2.1]
# Apache/2.0.48 (Trustix Secure Linux/Linux) PHP/4.3.4
# Apache/2.0.50 (Linux/SUSE)
# Apache/2.0.55 (Ubuntu) PHP/4.4.2-1build1
# Apache/2.2.2 (Unix) mod_ssl/2.2.2 OpenSSL/0.9.7l
+++:XML:200:200:200:501:200:HTM:XML:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.(4[89]|5[0-9])|2\.[0-2]) \(Ubuntu|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/2.0.48-2.2.2 (Linux)
# Apache/2.0.48 (Fedora) - X-Powered-By: PHP/4.3.4
+++:HTM:200:200:200:200:200:HTM:HTM:302:302:400:302:302:302:200:302:302:200:+++:Apache/2.0 (Unix)::Apache/2.0.48 (Fedora) [w/ PHP/4.3.4]
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:VER:405:405:200:405:501:200:+++:Apache/2.0 (Unix)::Apache/2.0.51 (Trustix Secure Linux/Linux) mod_ssl/2.0.51 OpenSSL/0.9.7c PHP/4.3.9
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.44 (Unix)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.48 (Fedora)
# Apache/2.0.49 (Fedora)
# Apache/2.0.49 (Linux/SuSE)
# Apache/2.0.50 (Fedora)
# Apache/2.0.51 (Turbolinux)
# Apache/2.0.52 (CentOS)
# Apache/2.0.53 (Linux/SUSE)
# Apache/2.0.54 (Linux/SUSE)
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 PHP/4.3.10-18
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 SVN/1.1.4 PHP/4.3.10-16
# Apache/2.0.54 (Mandriva Linux/PREFORK-13.3.20060mdk)
# Apache/2.0.55 (Ubuntu) DAV/2 mod_python/3.1.4 Python/2.4.3 PHP/5.1.2 mod_ssl/2.0.55 OpenSSL/0.9.8a mod_perl/2.0.2 Perl/v5.8.7
# Apache/2.2.3 (Mandriva Linux/PREFORK-1mdv2007.0)
# Apache/2.2.3 (Unix) mod_ssl/2.2.3 OpenSSL/0.9.7e DAV/2
# Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.2.0
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache/2\.(0\.(4[0-9]|5[0-9])|2\.[0-3]) \(Fedora|CentOS|Red Hat( Linux)?|[A-Za-z ]+/Linux|Linux/SuSE\):Apache/2.0.40-2.2.3 (Linux)
#
+++:HTM:HTM:200:302:501:HTM:HTM:HTM:HTM:HTM:302:411:411:401:501:501:501:---:+++:WebSite/3.5::WebSite/3.5.17
+++:HTM:HTM:200:200:501:HTM:HTM:HTM:HTM:HTM:200:411:411:401:501:501:501:---:+++:WebSite/3.5::WebSite/3.5.17
+++:200:HTM:200:200:501:HTM:HTM:HTM:HTM:HTM:200:411:411:401:501:501:501:---:+++:WebSite/3.5::WebSite/3.5.19
+++:HTM:HTM:200:200:501:HTM:HTM:HTM:HTM:HTM:200:411:411:403:501:501:501:---:+++:WebSite/3.5::WebSite/3.5.19
# http://www.tnsoft.com -> IA WebMail Server
+++:200:200:200:200:200:200:200:200:200:200:200:+++:200:200:200:200:200:+++:+++:::WebMail/1.0 [IA WebMail Server version 3.1?]
# Conflicting & unconfirmed
# WSTL CPE 1.0
# Confirmed
# TRMB/1.0 [Trimble NetR5 Receiver]
200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:---:---:^(WSTL CPE 1\.0|TRMB/1\.0)::WSTL CPE 1.0 or Trimble NetR5 Receiver [very fuzzy signature]
# Guardant Net Server
# httpd 0.0.7
200:200:200:200:200:200:200:200:200:200:200:200:---:200:200:200:200:200:200:200:::Guardant Net Server or httpd 0.0.7 ??
#
200:400:400:200:200:400:400:400:400:404:404:200:200:400:400:400:400:400:200:404:::Gatling/0.11
400:400:405:505:505:401:400:400:400:401:401:401:401:405:405:401:501:501:400:400:GigaTribe::GigaTribe/2.50
# Eudora
+++:HTM:400:200:HTM:200:HTM:HTM:HTM:400:400:200:400:400:400:400:400:400:404:+++:::WorldMail-HTTPMA/6.1.19.0
## A every common Apache signature ##
+++:---:200:200:302:501:302:HTM:---:400:400:400:404:405:405:403:405:501:302:+++:Apache/2.0 (Unix)::Apache/2.0.48 (Unix) Debian GNU/Linux
# Apache/2.0.48 w/ full modules support, compiled with openssl 0.9.7c Kernel 2.4.24 on RedHat 9.0 distribution
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 SVN/1.1.4 mod_jk2/2.0.4 PHP/4.3.10-18 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_perl/1.999.21 Perl/v5.8.7
# Apache/2.2.3 (Debian) DAV/2 PHP/4.4.4-6 mod_ssl/2.2.3 OpenSSL/0.9.8c mod_musicindex/1.1.3
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:403:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.(4[89]|5[0-9])|2\.[0-3]) \(Debian[A-Za-z/]*|Unix\):Apache/2.0.48-2.2.3 (Unix)
# Fedora core release 1 5Yarrow)
# php-4.3.4-1.1, php-ldap-4.3.4-1.1, php-mysql-4.3.4-1.1, php-imap-4.3.4-1.1, httpd-2.0.48-1.2, mod_ssl-2.0.48-1.2, mod_python-3.0.4-0.1
# mod_auth_mysql-20030510-3, mod_perl-1.99_12-2
+++:xxx:200:200:200:200:200:xxx:xxx:302:302:400:404:302:302:200:302:302:200:+++:Apache/2.0 (Unix)::Apache/2.0.48 (Fedora)
# Apache 2.0.48 on Solaris 8
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:---:404:405:405:200:405:501:---:+++:Apache/2.0 (Unix)::Apache/2.0.48 (Unix) [Solaris 8]
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.59 (FreeBSD) PHP/4.4.4 with Suhosin-Patch mod_ruby/1.2.5 Ruby/1.8.5(2006-08-25) mod_ssl/2.0.59 OpenSSL/0.9.7e
# Apache/2.2.0 (Fedora)
+++:HTM:200:200:200:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.0) \([A-Za-z /]*Linux|FreeBSD|Fedora\):Apache/2.0.40-2.2.0 (Unix)
# Fake banner: Apache/2.2.0 (Fedora) PHP/5.2.11-pl0-gentoo
HTM:HTM:200:505:505:505:200:HTM:HTM:400:400:400:400:405:405:405:405:501:200:404:Apache/2.2:^Apache/2\.2:Apache/2.2.11 (Linux) mod_security
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.48 (Linux/SuSE)
# Apache/2.0.53 (Linux/SUSE)
+++:XML:200:200:200:200:200:XML:XML:400:400:400:200:200:200:200:200:200:200:+++:Apache/2.0 (Unix):Apache/2\.0\.(4[0-9]|5[0-3]) \([A-Za-z /]*Linux[A-Za-z /]*\):Apache/2.0.40-53 (Linux)
+++:HTM:200:200:200:501:200:HTM:HTM:302:301:400:302:405:405:200:405:405:403:+++:Apache/2.0 (Unix)::Apache/2.0.46 (Red Hat)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.46 (Unix) mod_perl/1.99_09 Perl/v5.8.0 mod_ssl/2.0.46 OpenSSL/0.9.7a DAV/2 FrontPage/5.0.2.2634 PHP/4.3.3 mod_gzip/2.0.26.1a
# Apache/2.0.59 (Unix) DAV/2 PHP/5.1.6
# Apache/2.2.0 (Fedora)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:200:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache/2\.(0\.(4[6-9]|5[0-9])|2\.0) \(Unix|Red Hat|Fedora|[A-Za-z /]*Linux\):Apache/2.0.46-2.2.0 (Unix)
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:403:403:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
+++:HTM:200:200:200:501:200:HTM:HTM:200:400:400:200:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.48 (Fedora)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:302:+++:Apache/2.0 (Unix):^Apache/2\.0\.4[6-8] \(Red Hat|Fedora\):Apache/2.0.46-48 (Red Hat)
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:302:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux) mod_perl/1.99_07-dev Perl/v5.8.0 PHP/4.2.2 mod_ssl/2.0.40 OpenSSL/0.9.7a DAV/2 JRun/4.0
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.55 (Gentoo) mod_ssl/2.0.55 OpenSSL/0.9.7i DAV/2 PHP/4.4.0-pl1-gentoo
# # Apache/2.2.2 (Unix) mod_ssl/2.2.2 OpenSSL/0.9.8d DAV/2 PHP/5.1.4
# Apache/2.2.3 (Fedora) [w/ PHP/5.1.6]
+++:XML:200:200:200:200:200:XML:XML:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.[0-3]) \([A-Za-z /]*Linux|Gentoo|Unix|Fedora\):Apache/2.0.40-2.2.3 (Unix)
# Apache/2.0.48 (Unix) PHP/4.3.3
# Apache/2.0.48 (Fedora) PHP/4.3.4
# Apache/2.0.52 (Debian GNU/Linux)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:+++:Apache/2.0 (Unix):Apache/2\.0\.(4[89]|5[0-2]) \(Unix|Fedora|[A-Za-z /]*Linux\):Apache/2.0.48-52 (Unix)
+++:XML:200:200:200:501:200:HTM:XML:400:400:400:404:201:404:200:404:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.50 (Debian GNU/Linux) DAV/2 SVN/1.0.5 mod_python/3.1.3 Python/2.3.4
# Apache/2.0.50 (Unix) PHP/4.3.7
# Apache/2.0.52 (Gentoo/Linux)
# Apache/2.0.54 (Gentoo/Linux)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:403:405:501:200:+++:Apache/2.0 (Unix):^Apache(/2\.0\.5[0-4] \((Unix|[a-zA-Z/]*Linux).*)?$:Apache/2.0.50-54 (Unix)
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.48 (Linux/SuSE)
# Apache/2.0.48 (Unix) mod_ssl/2.0.48 OpenSSL/0.9.7c PHP/4.3.4
# Apache/2.0.49 (Linux/SuSE) [SuSE Linux 9.1]
# Apache/2.0.52 (NETWARE) mod_jk/1.2.6a
# Apache/2.0.55 (Debian) PHP/4.4.2-1.1 mod_ruby/1.2.6 Ruby/1.8.4(2005-12-24)
# Apache/2.0.55 (Ubuntu) PHP/5.1.2 mod_ssl/2.0.55 OpenSSL/0.9.8a
# Apache/2.2.0 (Unix)
# Apache/2.2.3 (Unix) mod_ssl/2.2.3 OpenSSL/0.9.7k PHP/5.1.6
# Apache/2.2.3 (Unix) mod_ssl/2.2.3 OpenSSL/0.9.8b PHP/5.1.5
# Apache/2.2.3 (Mandriva Linux/PREFORK-1mdv2007.0)
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache/2\.(0\.(4[0-9]|5[0-9]|2\.[0-3]) \(Unix|NETWARE|Ubuntu|[A-Za-z ]*Linux[/A-Za-z0-9. -]*\):Apache/2.0.40-2.2.3 on Unix or NETWARE
# Same as above, less precise
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:501:+++:+++:::Rational_Web_Platform [Clearcase Webserver]
# Apache/2.0.49 (Unix) PHP/4.3.7
# Apache/2.0.50 (Unix) mod_ssl/2.0.50 OpenSSL/0.9.7i PHP/4.3.8 mod_python/3.1.3 Python/2.3.4
# Apache/2.0.54 (Debian GNU/Linux) PHP/4.3.10-16 proxy_html/2.4
# Apache/2.0.55 (Debian) PHP/4.4.2-1.1
# Apache/2.0.47 (Unix) FrontPage/5.0.2.2626
# Apache/2.2.2 (Unix) mod_ssl/2.2.2 OpenSSL/0.9.7j PHP/5.1.4
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:405:200:405:501:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):^Apache/2\.(0\.(4[7-9]|5[0-9])|2\.[0-2]) \(Unix|Debian|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/2.0.47-2.2.2 (Unix)
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:403:403:200:405:501:200:+++:Apache/2.0 (Unix)::Apache/2.0.49 (Linux/SuSE)
+++:400:400:200:400:400:400:400:400:400:400:200:404:405:405:200:405:400:403:+++:Apache/2.0 (Unix)::Apache/2.0.49 (Unix) mod_python/3.1.3 Python/2.3.4
# httpd-2.0.52-9.ent on RedHat Enterprise Server v4 ES 2.6.9-5.ELsmp
+++:HTM:200:200:404:404:404:HTM:HTM:400:400:400:404:405:405:200:405:405:404:+++:Apache/2.0 (Unix)::Apache/2.0.52-9 [w/ PHP/4.3.9 on Redhat ES]
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:400:+++:Apache/2.0 (Unix)::Apache/2.0.49 (Unix) mod_ssl/2.0.49 OpenSSL/0.9.7d Resin/3.0.7 JRun/4.0
# The httpd.conf differs from redhat distribution by rewrite stuff to disable TRACE/TRACK and by .htaccess being enabled. No virtual domains.
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:403:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux) [w/ PHP/4.2.2 and mod_dav]
# Apache/2.2.3 (Mandriva Linux/PREFORK-1mdv2007.0)
# Apache/2.2.4 (Mandriva Linux/PREFORK-6mdv2007.1)
+++:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:403:405:501:200:+++:Apache/2.2 (Unix):Apache/2.2.3 (Mandriva Linux/PREFORK-[0-9]mdv200[0-9]\.[0-9]):Apache/2.2 (Mandriva Linux)
# More precise
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:403:405:501:200:403:Apache/2.2 (Unix)::Apache/2.2.14 (Unix) mod_ssl/2.2.14 OpenSSL/0.9.7l PHP/5.2.14
# Secure Web Server 6.7.1 for Tru64 UNIX (powered by Apache)
# software release: Secure Web Server, version 6.7.1 (Apache 2.2)
# operating system release: Tru64 Unix 5.1B-4
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:200:200:403:200:200:200:403:Apache/2.2 (Unix):Apache:Secure Web Server 6.7.1 for Tru64 UNIX (powered by Apache)
HTM:HTM:200:200:301:301:301:HTM:HTM:400:400:400:404:405:405:200:405:501:301:301:Apache/2.2 (Linux)::Apache/2.2.9 (Debian) mod_ssl/2.2.9 OpenSSL/0.9.8g
# Apache 2.2.9-10+lenny6 (protected web server)
HTM:HTM:200:401:401:401:401:HTM:HTM:400:400:400:401:401:401:405:401:401:401:401:Apache/2.2 (Unix):Apache:Apache/2.2.9 (Unix)
# apache2-2.2.16-6+squeeze
HTM:HTM:200:200:301:301:301:HTM:HTM:400:400:400:404:405:405:405:405:501:301:301:Apache/2.2 (Linux)::Apache/2.2.16 (Linux)
# www-servers/apache-2.2.11 - same sig with or w/out USE='apache2_mpms_prefork -threads'
# Apache 2.2.16 on Debian 6.0.7
# Apache/2.2.8 on Gentoo (Apache/2.2.8 (Gentoo) mod_ssl/2.2.8 OpenSSL/0.9.8g PHP/5.2.8-pl2-gentoo)
# Apache/2.2.11 (Gentoo) mod_ssl/2.2.11 OpenSSL/0.9.8k PHP/5.2.11-pl0-gentoo
# Apache/2.2.17 (Gentoo) mod_ssl/2.2.17 OpenSSL/1.0.0d
# Apache 2.2.8 on Ubuntu 8.04.4 LTS
# Apache 2.2.14 on Ubuntu 10.04.4 LTS
# Apache/2.2.17 (Ubuntu)
# Apache 2.2.20 on Ubuntu 11.10
# Apache 2.2.22 on Ubuntu 12.04
# Apache 2.2.22 on Ubuntu 12.10
# Apache 2.4.3 on Slackware 14.0
# Apache 2.4.6 on Slackware 14.1
# Apache 2.4.6 on Ubuntu 13.10
# Apache 2.4.7 on Ubuntu 14.04
# Apache 2.4.10 on Ubuntu 14.10
#
# nb: some of these return two different fingerprints.
---:---:---:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:501:200:404:Apache/2.2 (Linux) or Apache/2.4 (Linux):^Apache/2\.(2\.(8|1[1-9]|2[02])|4\.[367]) \((Debian|Gentoo|Ubuntu|Unix)\):Apache/2.2.8-22 or Apache/2.4.3-7 (Linux)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:405:405:501:200:404:Apache/2.2 (Linux) or Apache/2.4 (Linux):^Apache/2\.(2\.(8|1[1-9]|2[0-5])|4\.([67]|10|12)) \((Debian|Gentoo|Ubuntu)\):Apache/2.2.8-25 (Linux) or Apache/2.4.6-12 (Linux)
# Apache 2.4.10 on Ubuntu 14.10
---:---:200:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:501:200:404:Apache/2.4 (Linux):^Apache/2\.4\.10 \(Ubuntu\):Apache/2.4.10 (Ubuntu)
# Apache 2.2.15 on CentOS 6.3 (httpd-2.2.15-28.el6.centos.i686)
---:---:---:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:405:200:404:Apache/2.2 (Linux):^Apache/2\.2\.15 \(CentOS\):Apache/2.2.15
# Apache 2.2.14 on Citrix NetScaler 10.0
# Apache 2.4.9 on FreeBSD 9.3
# Apache 2.4.6 on FreeBSD 10.0
# Apache 2.4.6 on NetBSD 5.1.3
# Apache 2.4.6 on NetBSD 5.2.1
# Apache 2.4.6 on NetBSD 6.0.3
# Apache 2.4.6 on NetBSD 6.1.2
---:---:---:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:501:200:403::^Apache:Apache/2.2 on Citrix NetScaler or Apache/2.4.9 on FreeBSD 9.3 or Apache/2.4.6 on FreeBSD 10.0 or Apache/2.4.6 on NetBSD 5.1.3 / 5.2.1 / 6.0.3 / 6.1.2
# Apache 2.4.6 on FreeBSD 10.0 (alternate)
# Apache 2.4.10 on FreeBSD 10.1
---:---:200:200:200:---:200:HTM:---:400:400:400:404:405:405:---:405:501:200:403:Apache/2.4:^Apache/2\.4\.(6|10) \(FreeBSD\):Apache/2.4.6 on FreeBSD 10.0 or Apache/2.4.10 on FreeBSD 10.1
# Apache/2.0.59 on SLES 9.4
# Apache/2.4.6 on OpenSuSE 13.1
# Apache/2.4.16 on OpenSuSE 42.1
# Apache/2.4.10 on OpenSuSE 13.2
#
# nb: this returns two different fingerprints.
XML:XML:200:403:403:501:403:XML:XML:400:400:400:404:405:405:200:405:501:403:404:Apache/2.0 (Linux) or Apache/2.4 (Linux):^Apache/2\.(0\.59|2\.29|4\.(6|10|16)) \(Linux/S[uU]SE\):Apache/2.0.59 (Linux/SUSE) or Apache/2.2.29 (Linux/SUSE) or Apache/2.4.6 (Linux/SUSE) or Apache/2.4.16 (Linux/SUSE) or Apache/2.4.10 (Linux/SUSE)
---:---:---:403:403:---:403:XML:---:400:400:400:404:405:405:---:405:501:403:404:Apache/2.0 (Linux) or Apache/2.4 (Linux):^Apache/2\.(0\.59|4\.(6|16)) \(Linux/S[uU]SE\):Apache/2.0.59 (Linux/SUSE) or Apache/2.4.6 (Linux/SUSE) or Apache/2.4.16 (Linux/SUSE)
# Apache/2.2.17 on openSUSE 11.4
# Apache/2.2.3 on SLES 10.4
# Apache/2.2.12 on SLES 11.1
#
# nb: these return two different fingerprints.
XML:XML:200:403:403:501:403:400:400:400:400:400:404:405:405:200:405:501:403:404:Apache/2.2 (Unix):^Apache/2\.2\.(3|1[27]) \(Linux/SUSE\):Apache/2.2.3-17 (Linux/SUSE)
---:---:---:403:403:---:403:400:---:400:400:400:404:405:405:---:405:501:403:404:Apache/2.2 (Unix):^Apache/2\.2\.(3|1[27]) \(Linux/SUSE\):Apache/2.2.3-17 (Linux/SUSE)
# Apache/2.2.12 on SLES 11.4
XML:XML:200:400:400:400:400:400:---:400:400:400:404:405:405:200:405:501:403:404::^Apache/2\.2\.12:Apache/2.2.12 (Linux/SUSE) [R]
# Apache/2.2.22 (Ubuntu)
HTM:HTM:200:403:403:403:403:HTM:HTM:400:400:400:404:405:405:405:405:501:414:414:::Apache/2.2.22 (Ubuntu)
# Apache/2.2.20 (Gentoo) mod_ssl/2.2.20 OpenSSL/1.0.0d
# Apache/2.2.21 (Gentoo) mod_ssl/2.2.21 OpenSSL/1.0.0e
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:405:405:405:501:200:404:Apache/2.2 (Unix):^Apache/2\.2\.2[01] \(Gentoo\):Apache/2.2.20-2.2.21 (Gentoo)
# Apache/2.2.21 on openSUSE 12.1
# Apache/2.2.22 on openSUSE 12.2
# Apache/2.2.22 on openSUSE 12.3
#
# nb: these return two different fingerprints.
XML:XML:200:403:403:501:403:HTM:HTM:400:400:400:404:405:405:200:405:501:403:404:Apache/2.21 (Unix):^Apache/2\.2\.2[12] \(Linux/SUSE\):Apache/2.2.21-2.2.22 (openSUSE 12.x)
---:---:---:403:403:---:403:HTM:---:400:400:400:404:405:405:---:405:501:403:404:Apache/2.21 (Unix):^Apache/2\.2\.2[12] \(Linux/SUSE\):Apache/2.2.21-2.2.22 (openSUSE 12.x)
# Apache/2.2.3 on CentOS 5.9
# Apache/2.2.15 on CentOS 6.4
# Apache 2.2.23 on Fedora 17
# Apache 2.4.3 on Fedora 18
# Apache 2.4.4 on Fedora 18
# Apache 2.4.6 on Fedora 19
# Apache 2.4.6 on Fedora 20
# Apache/2.0.52 on Oracle 4.9
# Apache/2.2.3 on Oracle 5.9
# Apache/2.2.15 on Oracle 6.4
# Apache/2.0.52 on Red Hat 4.9
# Apache/2.2.3 on Red Hat 5.9
# Apache/2.2.15 on Red Hat 6.4
# Apache/2.2.3 on Scientific Linux 5.9
# Apache/2.2.15 on Scientific Linux 6.3
---:---:---:403:403:---:403:HTM:---:400:400:400:404:405:405:---:405:405:403:404:Apache/2.0 (Unix), Apache/2.2 (Unix) or Apache/2.4 (Unix):^Apache/2\.(0\.52|2\.(3|15|23)|4\.[346]) \(CentOS|Fedora|Oracle|Red Hat|Scientific Linux\):Apache/2.0.52, Apache/2.2.3-2.2.23 or Apache/2.4.3-6 (Unix)
# Apache/2.4.6 on CentOS 7.0
# Apache/2.4.6 on Oracle Linux 7.0
# Apache/2.4.6 on Scientific Linux 7.0
---:---:200:403:403:---:403:HTM:---:400:400:400:404:405:405:---:405:405:403:404:Apache/2.4:Apache/2\.4\.6 \(CentOS|Red Hat|Scientific Linux\):Apache/2.4.6 on Red Hat / CentOS / Oracle Linux / Scientific Linux
# Apache/2.2.22 (Mandriva Linux/PREFORK-0.1mdv2010.2)
# Apache/2.2.24 (Mandriva Linux/PREFORK-0.1)
# Apache/2.2.23 (Mandriva/PREFORK-1.mbs1)
# Apache/2.2.17 (Mageia/PREFORK-4.mga1)
# Apache/2.2.22 (Mageia/PREFORK-12.mga2)
# Apache/2.4.4 (Mageia)
# Apache/2.4.7 (Mageia)
---:---:---:200:200:---:200:XML:---:400:400:400:404:405:405:---:405:501:200:404::^Apache/2\.(2\.(17|2[2-4])|4\.[4-7]) \(((Mageia|Mandriva( Linux)?)/PREFORK|Mageia):Apache/2.2.17-24 or Apache/2.4.4-7 (Mageia or Mandriva Linux)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:405:405:501:200:404::^Apache/2\.(2\.(17|2[2-4])|4\.[4-7]) \(((Mageia|Mandriva( Linux)?)/PREFORK|Mageia):Apache/2.2.17-24 or Apache 2.4.4-7 (Mageia or Mandriva Linux)
#
#### Apache Win32 ####
#  Apache through ACC reverse proxy
# Or IBM_HTTP_SERVER/1.3.28
+++:HTM:400:HTM:HTM:HTM:200:400:400:400:400:200:404:400:400:200:501:501:200:+++:Apache/1.3 (Win32):Apache/1\.3\.28 \(Win32\):Apache/1.3.28 (Win32) through ACC reverse proxy or IBM_HTTP_SERVER/1.3.28
# Apache/1.3.27 (Win32)
# OpenSA/1.0.4 / Apache/1.3.27 (Win32) PHP/4.2.2 mod_gzip/1.3.19.1a DAV/1.0.3
# IBM_HTTP_SERVER/1.3.28.1  Apache/1.3.28 (Win32) mod_jk/1.2.15 PHP/5.0.4
# Apache/1.3.33 (Win32)
# Apache/1.3.34 (Win32) PHP/4.4.2 mod_ssl/2.8.25 OpenSSL/0.9.8a
HTM:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32):Apache/1\.3\.(2[7-9]|3[0-4]) \(Win32\):Apache/1.3.27-1.3.34 (Win32)
+++:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.23 (Win32)
+++:HTM:200:200:200:200:200:HTM:HTM:200:+++:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Win32)::Apache/1.3.24 (Win32) PHP/4.2.0
# IBM_HTTP_SERVER/1.3.20  Apache/1.3.20 (OS/2) PHP/4.1.1
# Apache/1.3.24 (Win32) PHP/4.2.0
+++:HTM:200:200:200:200:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32) or Apache/1.3 (OS/2):Apache/1\.3\.2[0-4] \((Win32|OS/2)\):Apache/1.3.20-24 (Win32 / OS/2) w/ PHP/4
+++:HTM:200:200:400:400:200:HTM:HTM:200:400:400:403:403:403:200:403:403:403:+++:Apache/1.3 (Win32)::Apache/1.3.26 (Win32) mod_perl/1.27
+++:---:200:200:400:400:200:HTM:---:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.26 (Win32) mod_jk/1.1.0 mod_ssl/2.8.9 OpenSSL/0.9.6d
+++:HTM:200:200:400:400:200:HTM:HTM:200:400:400:404:405:404:200:404:501:404:+++:Apache/1.3 (Win32)::Apache/1.3.26 (Win32) mod_jk/1.2.0 mod_ssl/2.8.10 OpenSSL/0.9.7d
# Apache/1.3.29 (Win32) PHP/4.3.4  X-Powered-By: PHP/4.3.4 - Win 2000 SP3
# Apache/1.3.27 (Win32)
# Apache/1.3.27 (Win32) PHP/4.3.0
# Apache/1.3.27 (Win32) PHP/4.3.3RC1
# Apache/1.3.29 (Win32) PHP/4.3.6
# Apache/1.3.35 (Win32) PHP/5.1.4
+++:HTM:200:200:400:200:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32):^Apache/1\.3\.(2[7-9]|3[0-5]) \(Win32\):Apache/1.3.27-35 (Win32) [w/ PHP4?]
+++:xxx:200:200:200:200:200:xxx:xxx:200:+++:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Win32)::Apache/1.3.24 (Win32) PHP/4.2.0
+++:xxx:200:200:400:400:200:HTM:xxx:200:+++:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Win32)::Apache/1.3.26 (Win32)
# Apache/1.3.26 (Win32) PHP/5.0.2
# Apache/1.3.26 (Win32) mod_jk/1.1.0
+++:HTM:200:200:400:400:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.26 (Win32)
+++:---:403:200:200:501:200:HTM:---:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::IBM_HTTP_SERVER/1.3.19.3 Apache/1.3.20 (Win32)
+++:HTM:403:200:404:501:404:HTM:HTM:404:400:400:200:200:200:200:200:200:403:+++:Apache/1.3 (Win32)::IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Win32)
+++:HTM:501:200:400:400:---:HTM:---:301:400:400:404:405:405:501:501:501:301:+++:Apache/1.3 (Win32)::IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Win32)
# Operating system : Windows NT4.0 SP 6.a
+++:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:403:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.29 (Win32) ApacheJServ/1.1.2 mod_ssl/2.8.16 OpenSSL/0.9.6m
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:+++:+++:Apache/1.3 (Win32)::Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# More precise!
# IBM_HTTP_Server/1.3.12.3 Apache/1.3.12 (Win32)
# IBM_HTTP_SERVER/1.3.19.3 Apache/1.3.20 (Win32)
# IBM_HTTP_SERVER/1.3.19.3  Apache/1.3.20 (Win32)
# TBD: control the 3 next signatures
# IBM_HTTP_Server/1.3.12.2 Apache/1.3.12
# IBM_HTTP_SERVER/1.3.19  Apache/1.3.20 (Win32)
# IBM_HTTP_Server/1.3.6.2 Apache/1.3.7-dev (Win32)
# Apache/1.3.12 (Win32)
# Apache/1.3.17 (Win32)
# Apache/1.3.20 (Win32)
# Apache/1.3.22 (Win32)
# Oracle HTTP Server Powered by Apache/1.3.19 (Win32) PHP/4.2.1 mod_ssl/2.8.1 OpenSSL/0.9.5a mod_fastcgi/2.2.10 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32):(Apache/1\.3.(1[2-9]|2[0-2]) \(Win32\)|^Oracle9iAS/9.0.2.3.0 Oracle HTTP Server$):Apache/1.3.12-22 (Win32) [may be IBM_HTTP_SERVER or Oracle HTTP Server]
# Even more precise
# Oracle HTTP Server Powered by Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.24
# Oracle HTTP Server Powered by Apache/1.3.22 (Win32) mod_plsql/3.0.9.8.3b mod_ssl/2.8.5 OpenSSL/0.9.6b mod_fastcgi/2.2.12 mod_oprocmgr/1.0 mod_perl/1.25
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32):^Oracle HTTP Server Powered by Apache/1\.3\.(1[2-9]|2[0-2]) \(Win32\) :Oracle HTTP Server Powered by Apache/1.3.12-1.3.22 (Win32)  mod_ssl/2.6.4-2.8.5 OpenSSL/0.9.5a-0.9.6b mod_perl/1.24-1.25
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:---:Apache/1.3 (Win32)::Oracle HTTP Server Powered by Apache/1.3.12 (Win32) ApacheJServ/1.1 mod_ssl/2.6.4 OpenSSL/0.9.5a mod_perl/1.24
#
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.22 (Win32)
# F-secure policy manager (based on Apache?)
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:200:501:404:501:403:404:FSPM::FSPMS/7.20 (Win32) mod_jk/1.2.5 mod_gzip/1.3.19.1a
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:501:404:501:403:404:FSPM::FSPMS/7.20 (Win32) mod_jk/1.2.5 mod_gzip/1.3.19.1a
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:404:501:404:200:403:404:FSPM::FSPMS/7.20 (Win32) mod_jk/1.2.5 mod_gzip/1.3.19.1a
xxx:xxx:403:500:500:500:500:xxx:xxx:500:400:400:500:500:500:500:500:500:500:500:FSPM::FSPMS/7.20 (Win32) mod_jk/1.2.5 mod_gzip/1.3.19.1a [broken configuration]
# IBM_HTTP_SERVER/1.3.26.2  Apache/1.3.26 (Win32)
# IBM_HTTP_SERVER/1.3.26  Apache/1.3.26 (Win32)
# Apache/1.3.27 (Win32)
# Apache/1.3.27 (Win32) PHP/4.3.0
# Apache/1.3.28 (Win32)
# Apache/1.3.28 (Win32) PHP/4.2.1
# Apache/1.3.28 (Win32) PHP/4.3.2
# OpenSA/1.0.4 / Apache/1.3.27 (Win32) PHP/4.2.2 mod_gzip/1.3.19.1a DAV/1.0.3
# Oracle-Application-Server-10g/10.1.2.0.2
# Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server
+++:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32):^((Oracle-Application-Server-10g/(9|10))|(Apache/(1\.3\.2[6-9] \(Win32\))?)):Apache/1.3.26-29 (Win32) [may be IBM_HTTP_SERVER/1.3.2x or OpenSA/1.0.x] or Oracle-Application-Server-10g
---:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32)::Apache/1.3.27 (Win32)
# Apache/1.3.17 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.5RC2-dev
# IBM_HTTP_SERVER/1.3.19.6 Apache/1.3.20 (Win32)
# Apache/2.0.44 (Win32) DAV/2
# Apache/2.0.55 (Win32) mod_ssl/2.0.55 OpenSSL/0.9.8a SVN/1.3.2 PHP/5.1.6 DAV/2
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:200:200:200:200:200:200:200:+++:Apache/1.3 (Win32) or Apache/2.0 (Win32):Apache/[12]\.[30]\.([14][4-9]|20|5[0-5]) \(Win32\):Apache/1.3.17-2.0.55 (Win32)
# More precise
# Apache/2.0.44 (Win32) DAV/2
# Apache/2.0.55 (Win32)
HTM:HTM:403:200:200:200:200:HTM:HTM:200:400:400:200:200:200:200:200:200:200:200:Apache/2.0 (Win32):Apache/2\.0\.|(4[4-9]|5[0-5]) \(Win32\):Apache/2.0.44-2.0.55 (Win32)
#
+++:HTM:200:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32)::Apache/2.0.43 (Win32) JRun/4.0
# Apache/2.0.48 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.4
# Apache/2.0.49 (Win32)
# Apache/2.0.47 (Win32)
# Apache/2.0.54 (Win32)
# Apache/2.0.55 (Win32) PHP/5.1.2
# Apache/2.0.59 (Win32)
# Apache/2.0.59 (Win32) PHP/4.4.4
# Apache/2.2.3 (Win32)
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):^Apache/2\.(0\.(4[4-9]|5[0-9])|2\.[0-3]) \(Win32\):Apache/2.0.47-2.2.3 (Win32)
# Apache/2.0.39 (Win32) mod_ssl/2.0.39 OpenSSL/0.9.6d
# Apache/2.0.39 (Win32) PHP/4.2.2
# Apache/2.0.35 (Win32)
+++:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:403:+++:Apache/2.0 (Win32):^Apache/2\.0\.3[5-9].*Win32:Apache/2.0.35-39 (Win32)
# Apache/2.0.40 (Win32)
# Apache/2.0.43 (Win32)
+++:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32):^Apache/2\.0\.4[0-3] \(Win32\):Apache/2.0.40-43 (Win32)
# More precise & conflicting
# Apache/2.2.8 (Win32)
# Apache/2.2.8 (Win32) PHP/5.2.6
# Apache/2.2.9 (Win32) PHP/5.2.6
# Apache/2.2.11 (Win32)
# Apache/2.2.14 (Win32) PHP/5.2.11
# Apache/2.2.15 (Win32)
# Apache/2.2.16 (Win32) PHP/5.2.0-dev
HTM:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Win32):^Apache(/2\.2\.([89]|1[0-9]|2[0-2]) \(Win32\)|$): Apache/2.2.8-2.2.22 (Win32)
# Apache/2.0.47 (Win32) PHP/4.3.4
# Apache/2.0.44 (Win32)
# Apache/2.0.48 (Win32) PHP/4.3.5
# Apache/2.0.49 (Win32) PHP/4.3.5
# Apache/2.0.53 (Win32) PHP/5.0.4
# Apache/2.0.53 (Win32) PHP/5.0.5-dev
# Apache/2.0.54 (Win32) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/5.0.2
# Apache/2.0.55 (Win32)
# Apache/2.0.59 (Win32) PHP/5.0.4
# Apache/2.2.2 (Win32) PHP/5.2.0-dev
# Apache/2.2.3 (Win32) PHP/5.1.4 mod_perl/2.0.3-dev Perl/v5.8.7
# Apache/2.2.3 (Win32) PHP/5.2.0
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):^Apache/2\.(0\.(4[4-9]|5[0-9])|2\.2\.[0-3]) \(Win32\):Apache/2.0.44-2.2.3 (Win32)
# More precise
# Apache/2.0.45 (Win32) PHP/4.4.2
# Apache/2.0.53 (Win32) PHP/5.0.3
# Apache/2.2.3 (Win32) PHP/5.2.0
# Apache/2.2.4 (Win32) PHP/5.2.3
# Apache/2.2.6 (Win32) PHP/4.4.4
HTM:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Win32) or Apache/2.2 (Win32):Apache/2\.(0\.(4[5-9]|5[0-9])|2\.[0-6]):Apache/2.0.45-2.2.4 (Win32) PHP/4 or PHP/5
# Apache/2.0.44 (Win32) PHP/4.3.1
# Apache/2.0.44 (Win32) PHP/4.3.1-dev
# Apache/2.0.48 (Win32)
# Apache/2.2.3 (Win32) PHP/5.2.0RC4-dev
+++:HTM:403:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):^Apache/2\.(0\.(4[4-9]|5[0-9])|2\.[0-3]) \(Win32\):Apache/2.0.44-2.2.3 (Win32)
+++:HTM:403:200:200:403:200:XML:HTM:200:400:400:404:403:403:403:403:403:200:+++:Apache/2.0 (Win32)::Apache/2.0.46 (Win32) mod_ssl/2.0.45 OpenSSL/0.9.7b
+++:HTM:403:503:503:500:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32)::Apache/2.0.48 (Win32) mod_jk2/2.0.4-dev
# Apache 2.0.55.0 PHP 5.1.2.2 on Windows 2000 Professional Build 2195
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:302:302:302:302:302:302:200:+++:Apache/2.0 (Win32)::Apache/2.0.55.0 (Win32) [w/ PHP/5.1.2.2]
# Uniform Server v3.3 on Windows XP Pro SP2
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:201:404:200:404:405:200:+++:Apache/2.0 (Win32)::Apache/2.0.55 (Win32) DAV/2 PHP/5.1.1
HTM:HTM:200:200:200:200:200:HTM:HTM:200:400:400:200:200:200:405:200:200:200:200:Apache/2.2 (Win32)::Apache/2.2.11 (Win32)
HTM:HTM:200:401:401:401:401:HTM:HTM:401:400:400:401:401:401:405:401:401:401:401:Apache/2.2 (Win32)::Apache/2.2.11 (Win32)
################
# A secure web server that crashes when it receives 'GET\r\n\r\n' :)
+++:200:301:200:200:301:301:301:---:404:404:200:404:301:301:301:301:301:200:+++:Anti-Web V3.0:^Anti-Web V3\.0\.2:Anti-Web V3.0.2
+++:200:301:200:200:301:301:301:404:404:404:200:404:301:301:301:301:301:200:+++:Anti-Web V3.0:^Anti-Web V3\.0\.3:Anti-Web V3.0.3 [fixed by MA]
+++:---:---:200:200:---:---:---:---:200:200:200:---:---:---:---:---:---:200:+++:Azureus 2.2::Azureus 2.2.0.2
+++:HTM:501:200:200:501:200:HTM:HTM:400:400:200:501:501:501:501:501:501:200:+++:::awkhttp.awk/-1.99.8
# What is BATM?
+++:200:---:200:200:200:200:---:404:404:+++:200:---:---:---:---:---:---:+++:+++:::BATM
# HP OpenView Embedded BBC Web Server
+++:---:404:505:505:404:505:505:505:---:404:404:+++:404:404:404:404:404:+++:+++::^BBC:HP OpenView BBC Web Server
---:---:404:505:505:404:505:505:505:---:404:404:404:404:404:404:404:404:404:---::^BBC:HP OpenView BBC Web Server
# Very unreliable...
# Sawmill/7.2.8
# Sawmill/8.1.9.1
# BCReport/8.3.2.2
200:200:200:200:200:200:200:200:200:200:200:400:200:200:200:200:200:200:200:200:BCReport/Sawmill:^(BCReport|Sawmill):BCReport/8.3.2.2 or Sawmill/7-8
# belkin Wireless broadband router (4 Port); Firmware Version:V1.10.008; Boot Version:V1.13; Hardware :01
+++:400:400:200:200:400:400:400:400:404:404:200:404:400:400:400:400:400:400:+++::^$:Belkin wireless broadband router
# See http://www.myipis.com/
+++:404:404:200:200:200:404:404:404:404:404:200:404:404:404:404:404:404:404:+++:::BlackcombHTTP Server (beta 0.4)
# Microsoft 2003 server with IIS6 and Tomcat, behind a BlueCoatSG proxy
403:403:400:400:400:403:403:400:400:400:400:403:411:411:501:501:501:501:403:403:BlueGoatSG:^$:Microsoft-IIS/6 with Tomcat, behind BlueCoatSG proxy
# bozohttpd/20031005 on FreeBSD 5.2.1, thru inetd
# bozohttpd/20040823 on Gentoo, thru inetd
# bozohttpd/20060517 on Gentoo, daemon mode
+++:200:404:404:404:200:200:404:404:404:404:400:400:404:404:404:404:404:403:+++:::bozohttpd
# bozohttpd/20080303 on NetBSD 5.1.3, through inetd
# bozohttpd/20080303 on NetBSD 5.1.4, daemon mode
# bozohttpd/20080303 on NetBSD 5.2.1, through inetd
# bozohttpd/20080303 on NetBSD 5.2.2, daemon mode
---:---:---:404:404:---:200:404:---:200:200:400:400:200:200:---:200:200:403:---::^bozohttpd:bozohttpd/20080303 on NetBSD 5.1.3 / 5.1.4 / 5.2.1 / 5.2.2
# bozohttpd/20111118 on NetBSD 6.1
# bozohttpd/20111118 on NetBSD 6.0.2
# bozohttpd/20111118 on NetBSD 6.0.3
# bozohttpd/20111118 on NetBSD 6.0.4 daemon mode
# bozohttpd/20111118 on NetBSD 6.1.3 daemon mode
---:---:---:404:404:---:200:404:---:200:200:400:400:200:200:---:200:200:403:500::^bozohttpd/20111118:bozohttpd/20111118 on NetBSD 6.0.2 / 6.0.3 / 6.0.4 / 6.1 / 6.1.3
+++:200:---:200:200:---:200:---:---:200:404:200:---:---:---:---:---:---:404:+++:::bttrack.py/3.4.2 [BitTorrent tracker]
# MA: I suspect that Bull-SMW is based on CERN httpd
+++:HTM:400:200:200:400:200:HTM:HTM:200:403:200:+++:403:403:400:400:400:+++:+++:::Bull-SMW/1.1
+++:404:404:200:200:404:404:404:404:404:404:200:200:404:404:404:404:404:+++:+++:::CERN/3.0 [Edimax Broadband router type BR-6004]
+++:HTM:400:200:200:400:200:HTM:HTM:403:+++:200:500:403:403:400:400:400:+++:+++:::CERN/3.0
+++:HTM:400:200:200:400:200:HTM:HTM:403:+++:200:200:403:403:400:400:400:+++:+++:::CERN/3.0
+++:HTM:400:200:200:400:200:HTM:HTM:403:+++:200:403:403:403:400:400:400:+++:+++:::CERN/3.0pre6vms3
# Boa 0.94.12 or 0.94.13
#HTM:501:HTM:HTM:501:501:501:501:400:+++:200:400:501:501:501:501:501:200::Boa/0\.94\.1[23]:Boa/0.94
# More precise
+++:HTM:501:HTM:HTM:501:501:501:501:400:400:200:400:501:501:501:501:501:200:+++:::Boa/0.94
# Even more - from a Iomega StorCenter Pro v69
HTM:HTM:501:HTM:HTM:501:501:501:501:400:400:200:400:501:501:501:501:501:200:HTM:::Boa/0.94.13
+++:HTM:400:200:HTM:HTM:200:400:400:404:+++:200:404:400:400:400:400:400:+++:+++:::Boa/0.92o
# More precise
HTM:HTM:400:200:HTM:HTM:200:400:400:404:404:200:404:400:400:400:400:400:200:---:::wg_httpd/1.0(based Boa/0.92q)
+++:HTM:501:400:400:501:501:501:400:400:400:200:400:501:501:501:501:501:400:+++:::Boa/0.94.14rc21
#
+++:200:200:200:400:400:400:400:400:404:+++:400:404:501:501:200:400:400:+++:+++:::Canon Http Server 1.00
+++:200:200:200:200:200:400:400:400:200:+++:+++:200:200:200:200:200:200:+++:+++:::Cassini/1.0.1403.33443
# Caudium/1.3.5 + X-Got-Fish: Pike v7.3 release 58
+++:500:501:200:200:501:500:500:xxx:404:+++:200:404:405:405:501:405:501:+++:+++:::Caudium/1.3.5 DEVEL (Debian GNU/Linux)
# Caudium/1.2.35 + X-Got-Fish: Pike v7.2 release 580
+++:500:501:200:200:501:500:500:xxx:404:302:200:404:405:405:501:501:501:200:+++:::Caudium/1.2.35 STABLE
+++:500:401:401:401:401:500:500:xxx:401:401:401:401:401:401:401:401:401:401:+++:::Caudium/1.2.35 STABLE [administration interface]
#
500:500:404:505:500:200:500:500:500:404:404:400:404:404:404:404:404:404:200:404:::CherryPy/3.0.2
VER:VER:404:505:500:302:VER:VER:VER:404:404:400:411:411:303:303:303:303:302:302:::CherryPy/3.1.2 [Splunk/4.2.2]
+++:xxx:xxx:xxx:xxx:xxx:xxx:xxx:xxx:400:400:200:404:xxx:xxx:xxx:xxx:xxx:404:+++:::Cherokee/0.4.2
+++:---:400:400:---:400:400:---:400:400:400:400:411:405:405:405:405:411:200:+++:::Cherokee/0.4.30 (Gentoo Linux)
# Cherokee/0.5.0 (Gentoo Linux) [basic configuration]
# Cherokee/0.5.1 (Gentoo Linux)
# Cherokee/0.5.2 (Gentoo Linux)
# Cherokee/0.5.5 (Gentoo Linux)
# Cherokee/0.5.6 (Gentoo Linux)
+++:---:400:400:---:400:400:---:400:400:400:400:411:404:404:404:404:411:200:+++:Cherokee/0.5:^Cherokee/0\.5\.[0-6] :Cherokee/0.5.0 to 0.5.6
# ...	# Cherokee/0.8.1
400:505:400:400:400:501:501:501:400:400:400:400:411:404:404:404:404:411:200:301:Cherokee/0.6-0.8:^Cherokee/0\.[6-8]\.[0-2]:Cherokee/0.6.0-0.8.1 (Gentoo Linux)
400:505:400:400:400:501:501:501:400:400:400:400:411:411:404:404:404:411:200:301:Cherokee/0.9::Cherokee/0.9.0 (Gentoo Linux)
# www-servers/cherokee-0.99.15, port 9090
400:505:400:400:400:501:501:501:400:400:400:400:411:411:401:401:401:411:401:401:::Cherokee/0.99.15 (Gentoo Linux) [administration interface]
# Cherokee/0.11.6 (Gentoo Linux)	# Cherokee/0.98.1 (Gentoo Linux)
# Cherokee/0.99.15 (Gentoo Linux)	# Cherokee/0.99.17 (Gentoo Linux)
# Cherokee/0.99.19 (Gentoo Linux)	# Cherokee/0.99.22 (Gentoo Linux)
400:505:400:400:400:501:501:501:400:400:400:400:411:411:404:404:404:411:200:404::Cherokee/0\.[1-9][0-9]\.[0-9]:Cherokee/0.11.6-0.99.22
# Cherokee/0.99.42 (Gentoo Linux)
# Cherokee/0.99.44 (Gentoo Linux)
# Cherokee/0.99.48 (Gentoo Linux)
# Cherokee/1.0.4 (Gentoo Linux)
# Cherokee/1.0.6 (Gentoo Linux)
# Cherokee/1.0.8 (Gentoo Linux)
400:505:411:400:400:501:501:501:400:400:400:400:411:411:404:404:404:411:200:404:cherokee:Cherokee/(0\.99\.4[2-9]|1\.0\.[0-8]):Cherokee/0.99.42-1.0.8
#
+++:400:400:200:200:400:400:400:400:200:200:200:404:400:400:400:400:400:---:+++::^$:Cisco Access Point AP4800E v8.80
# Fedora 23 Cockpit service on port 9090
---:---:405:---:---:---:---:---:---:400:400:400:405:405:405:405:405:405:400:400:::Cockpit Service [Fedora 23]
# Cisco Adaptive Security Appliance Software Version 7.0(6)
# Device Manager Version 5.0(6)
# Compiled on Tue 22-Aug-06 13:22 by builders
# shsasa up 77 days 20 hours
# Hardware:   ASA5510-K8, 256 MB RAM, CPU Pentium 4 Celeron 1600 MHz
# Internal ATA Compact Flash, 256MB
# BIOS Flash M50FW080 @ 0xffe00000, 1024KB
# Encryption hardware device : Cisco ASA-55x0 on-board accelerator (revision 0x0)
400:400:501:401:400:401:401:400:400:401:501:401:+++:501:501:501:501:501:+++:+++:Cisco-ASA:^$:Cisco Adaptative Security Appliance 7.0(6)
# Cisco ASA 5500 VPN
200:---:---:---:---:404:200:---:---:---:---:200:302:302:302:302:302:302:302:302:::Cisco-ASA:^$:Cisco ASA 5500 VPN
#
+++:---:405:505:400:200:---:400:400:400:400:400:+++:501:501:404:404:404:+++:+++:::cisco-IOS [12.3]
+++:xxx:405:505:400:200:200:400:400:400:400:400:411:501:501:404:404:404:+++:+++:::cisco-IOS
+++:400:501:200:400:200:200:---:---:200:501:200:200:501:501:501:501:501:+++:+++::^$:cisco-IOS 11.2
+++:---:501:200:400:200:200:---:---:200:501:200:200:501:501:501:501:501:200:+++::^$:cisco-IOS 11.2
# More precise
400:---:501:200:400:200:200:---:---:200:501:200:200:501:501:501:501:501:200:200::^$:cisco-IOS 11.2
+++:---:501:200:400:200:200:400:400:200:501:200:200:501:501:501:501:501:200:+++::^$:cisco-IOS 12.0(3)T, fc1 on a Cisco 1603
+++:---:501:200:400:200:200:---:---:200:501:200:---:501:501:501:501:501:+++:+++::^$:cisco-IOS/12.1 HTTP-server/1.0(1)
# Cisco Internetwork Operating System Software IOS (tm) C2900XL Software (C2900XL-C3H2S-M), Version 12.0(5.2)XU, MAINTENANCE INTERIM SOFTWARE
+++:---:501:200:400:200:200:---:---:200:501:200:200:501:501:501:501:---:+++:+++::^$:cisco-IOS 12.0(5.2)XU
+++:---:---:---:400:200:---:---:---:---:---:---:---:---:---:---:---:---:---:+++::^$:IOS Version 12.0(12), RELEASE SOFTWARE (fc1), running on a Cisco 1600
+++:200:---:200:200:---:---:---:---:200:---:200:200:---:---:---:---:---:+++:+++::^$:DSL modem Cisco 678 running CBOS
+++:200:500:200:200:500:500:500:200:500:500:200:500:500:500:500:500:500:+++:+++::^$:Cisco Secure ACS v3.0.x on Windows 2000
200:200:500:200:200:500:500:500:200:200:500:200:500:500:500:500:500:500:500:500:::^$:Cisco Secure ACS v4.0
+++:400:---:505:505:302:400:400:400:404:404:400:404:403:404:404:501:501:---:+++:::CL-HTTP/70.182 (Symbolics Common Lisp)
+++:400:400:200:400:200:400:400:400:400:400:200:404:400:400:400:400:400:404:+++:::Code Ocean Ocean Mail Server 1.06
# CUPS
+++:200:200:505:400:400:200:400:400:405:+++:200:401:403:---:---:400:400:+++:+++:::CUPS/1.1
200:200:200:505:400:400:200:400:400:405:403:200:401:403:---:---:400:400:400:400:::CUPS/1.1
+++:200:200:505:400:400:200:400:400:405:+++:200:404:403:---:---:400:400:+++:+++:::CUPS/1.1
+++:403:200:505:400:400:403:400:400:405:405:403:403:403:403:403:400:400:400:+++:::CUPS/1.1 [forbidden access]
+++:200:200:505:400:---:200:400:400:405:405:200:404:403:---:---:---:---:400:+++:::CUPS/1.2
200:200:200:505:400:---:200:400:400:405:405:200:404:403:---:---:---:---:400:400:::CUPS/1.2
# Compaq Web Management (?)
+++:---:---:---:---:---:---:---:---:200:405:200:404:405:---:---:---:---:+++:+++:::CompaqHTTPServer/1.0
+++:---:---:---:---:---:---:---:---:404:405:200:404:405:---:---:---:---:+++:+++:::CompaqHTTPServer/1.0 [Windows 2000]
# Conflicting signature
---:---:---:---:---:---:---:---:---:404:405:200:404:405:---:---:---:---:413:413:::CompaqHTTPServer/1.0 [Windows NT 4]
+++:---:510:---:---:---:---:---:---:404:405:200:404:405:---:---:---:---:+++:+++:::CompaqHTTPServer/2.1 [Windows NT]
+++:---:510:---:---:---:---:---:---:200:405:404:+++:405:---:---:---:---:+++:+++:CompaqHTTPServer/5:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.94
# More precise
+++:---:510:---:---:---:---:---:---:200:405:404:404:405:---:---:---:---:+++:+++:CompaqHTTPServer/5:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.9
# Compaq Insight (std install) on Windows 2000
+++:---:510:---:---:---:---:---:---:404:405:404:404:405:---:---:---:---:+++:+++:CompaqHTTPServer/4 or CompaqHTTPServer/5:^CompaqHTTPServer/[45]\.[012]:Compaq Insight 4.1 or 5.2 on Windows 2000
#
+++:---:510:---:---:---:---:---:---:200:+++:+++:200:405:---:---:---:---:+++:+++:CompaqHTTPServer/5::CompaqHTTPServer/5.0
# More precise
+++:---:510:---:---:---:---:---:---:200:405:200:+++:405:---:---:---:---:+++:+++:CompaqHTTPServer/5:^CompaqHTTPServer/5\.[7-9]:CompaqHTTPServer/5.7 to 5.91
+++:---:510:---:---:---:---:---:---:200:405:200:200:405:---:---:---:---:+++:+++:CompaqHTTPServer/5::CompaqHTTPServer/5.91
# Even more precise (but also 2.1??)
+++:---:510:---:---:---:---:---:---:200:405:200:200:405:---:---:---:---:413:+++:CompaqHTTPServer:CompaqHTTPServer/[2-5]\.:CompaqHTTPServer/2.1 to 5.94
---:---:510:---:---:---:---:---:---:200:405:200:200:405:---:---:---:---:413:413:::CompaqHTTPServer/5.0
+++:---:510:---:---:---:---:---:---:200:405:200:200:405:---:---:---:---:200:+++:CompaqHTTPServer/5::CompaqHTTPServer/5.7
# More precise / conflicting signature
---:---:510:---:---:---:---:---:---:200:405:200:200:405:---:---:---:---:200:200:CompaqHTTPServer/5:CompaqHTTPServer/5\.[0-9]:CompaqHTTPServer/5.0 to 5.94
#
+++:---:510:---:---:---:---:---:---:200:405:200:404:405:---:---:---:---:+++:+++:CompaqHTTPServer/2::CompaqHTTPServer/2.1
# Runs on Mac OSX Panther
+++:---:200:503:---:200:---:---:---:---:---:200:404:404:404:---:---:---:+++:+++:CommuniGatePro/4::CommuniGatePro/4.1.8
+++:---:200:---:---:200:---:---:---:---:---:200:404:404:404:---:---:---:404:+++:CommuniGatePro/4::CommuniGatePro/4.3.6
# Is Communique built on Apache?
+++:xxx:200:200:400:501:200:HTM:xxx:400:+++:400:404:405:404:403:404:501:+++:+++:::Communique/2.5.0 (build 4850)
# David-WebBox/6.60a (0297)
# David-WebBox/7.00a (0312)
# David-WebBox/7.00a (0314)
+++:---:---:200:200:200:200:---:---:302:200:200:302:302:302:---:---:---:302:+++:::David-WebBox
# IBM Desktop On Call 4.0 (?) on eComStation 1.1 (aka OS/2)
+++:HTM:---:200:200:200:404:404:404:200:+++:200:---:---:---:---:---:---:+++:+++:::Desktop On-Call HTTPD V3.0
# Novell eDirectory 8.7.3 HTTP server  (admin stuff)
+++:HTM:501:200:---:---:---:---:HTM:404:404:400:404:501:501:501:---:---:500:+++:::DHost/9.0 HttpStk/1.0
# DirectAdmin Daemon v1.32.2 Registered to [...]
# DirectAdmin Daemon v1.31.5 Registered to [...]
404:404:404:200:200:404:404:404:404:200:200:200:200:404:404:404:404:404:200:200:DirectAdmin:^DirectAdmin Daemon v1\.3[2-5]\.[0-2] Registered to:DirectAdmin Daemon v1.31.5-1.32.2
# Hardware:DSL-300G
# OS:D-Link Corp., Software Release R2.01M.B2.TA(021206a/T93.3.23)
+++:200:501:200:200:501:200:200:200:200:200:200:200:501:501:501:501:501:+++:+++::^$:D-Link ADSL router [DSL-300G Software Release R2.01M.B2.TA(021206a/T93.3.23)]
# Model: Vigor2600 annex A
# Firmware Version : v2.5_UK
# Build Date/Time : Fri Aug 29 21:0:23.61 2003
+++:HTM:400:200:200:400:HTM:HTM:HTM:400:302:200:501:400:400:400:400:400:+++:+++::^$:Draytek 2200 ADSL Vigor Router
# ADSL/Wifi Modem: SpeedTouch 706 - Software version: 6.1.7.2
# The Server field only appears on an invalid request like HELP
401:401:400:401:401:401:401:400:400:404:400:401:404:400:400:400:400:400:400:400::^(Speed Touch WebServer/1.0)?$:SpeedTouch 706 ADSL/Wifi Modem
+++:HTM:400:HTM:HTM:HTM:200:HTM:HTM:400:+++:200:500:405:405:405:501:501:+++:+++:::DECORUM/2.0
+++:HTM:405:HTM:HTM:HTM:200:HTM:HTM:200:+++:200:405:405:405:405:501:501:+++:+++:::DECORUM/2.0
+++:200:550:200:200:200:---:---:---:---:---:200:550:550:550:550:550:550:---:+++:::DManager [Surgemail 30c2 (windows XP)]
+++:505:400:505:505:505:200:505:505:404:404:200:400:400:400:400:400:400:200:+++:::DNHTTPD/0.6
# Web server (upsis.exe from OPTI-SAFE Xtreme) for monitoring & configuration of OPTI-UPS VS375C -- client version v3.2b
+++:400:501:501:501:400:400:400:400:200:404:400:+++:200:200:501:200:501:+++:+++:::dnpower [OPTI-SAFE Xtreme for OPTI-UPS]
+++:505:400:505:505:505:200:505:505:404:403:200:400:400:400:400:400:400:200:+++:::Ranquel-0.1.2
# On FreeBSD 5.2.1
+++:200:400:200:200:400:200:400:403:404:400:200:400:400:400:400:400:400:403:+++:::dhttpd/1.02a
# This is the AnswerBook.
+++:200:---:200:200:200:200:200:200:200:404:200:---:---:---:---:---:---:---:+++:::dwhttpd/4.2a7 (Inso; sun5)
# Easy File Sharing Web Server v4.5	# Easy File Sharing Web Server v4.6
200:200:---:200:200:200:---:---:---:200:403:200:---:---:---:---:---:---:200:400:::Easy File Sharing Web Server v4
+++:200:---:200:200:---:200:200:200:200:+++:200:---:---:---:---:---:---:+++:+++:::ELOG HTTP 2.3.6
+++:200:403:200:200:403:403:403:403:200:403:200:200:200:200:200:200:200:200:+++:::Embedded HTTPD v1.00, 1999(c) Delta Networks Inc.
# Embedded HTTP Server 2.05b3 [FIREBOX SOHO 6tc]
# Embedded HTTP Server 1.01 [D-Link DI-624+ Current Firmware Version: 1.01]
+++:xxx:501:VER:VER:VER:200:400:400:400:400:200:404:501:501:501:501:501:+++:+++:::Embedded HTTP Server
HTM:HTM:501:VER:VER:VER:401:400:400:400:400:401:404:501:501:501:501:501:400:404:::Embedded HTTP Server 1.00 [DLink EBR-2310]
#
+++:---:200:200:200:200:---:---:---:200:200:200:200:200:200:200:200:200:---:+++:::Apache/0.6.5 [Edimax broadband router, model 6104, version 0.59WD (Nov 07 2002 09:52:40)]
# emac-httpd thru xined :-)
+++:200:400:200:200:200:200:400:400:400:403:200:503:400:400:400:400:400:301:+++:::Emacs/httpd.el
+++:200:501:VER:VER:200:501:501:302:302:403:200:200:501:501:501:501:501:403:+++:::Fastream NETFile Web Server 7
# Fastream 11.4.7R
200:200:501:VER:VER:200:501:501:302:302:302:200:404:501:501:501:501:501:403:403:::Fastream IQ Web/FTP Server
+++:HTM:400:200:200:200:HTM:HTM:HTM:404:302:200:404:503:400:400:400:400:200:+++:::fhttpd
##200:200:404:200:200:200:---:200:200:---:---:---:---:404:404:+++:200:---:---:404:404:404:404:404:+++:FileMakerPro/4.0
# FMP 5.0 MacOS 8.6 - same as above, more precise
+++:200:404:200:200:200:---:---:---:404:404:200:---:---:404:404:404:404:+++:+++:::FileMakerPro/5.0
# WatchGuard SOHO (FTP Server version 2.4.19) internet security appliance
+++:200:401:200:200:404:---:---:---:401:401:200:401:401:401:401:401:401:+++:+++:::Firewall [SOS internet appliance]
# typical for Check Point Firewall-1 NG FP3 or NG AI versions
+++:200:---:200:200:200:---:---:---:200:---:200:---:---:---:---:---:---:+++:+++::^$:Check Point FW-1 NG HTTP authentication proxy
# Web management interfacce from Check Point's Secure Platform (RedHat Enterprise derived secure linux distro). NGX Rlease R60 Hot Fix Accumulator 03.
+++:---:404:---:---:---:---:---:---:200:404:200:+++:404:404:404:---:---:+++:+++:::Check Point SVN foundation [NGX Rlease R60 Hot Fix Accumulator 03]
# Version and build: Check Point FW-1 NGX R65 123 (SPLAT) - Installation type: VPN-1 Power Gateway
---:---:404:---:---:---:---:---:---:200:404:200:404:404:404:404:---:---:---:---:::Check Point SVN foundation [NGX R65 123 (SPLAT)]
+++:400:400:400:400:400:400:400:400:400:400:200:404:400:400:400:400:400:200:+++:fnord/1.8+:^fnord/1\.([89]|10):fnord/1.8-1.10
+++:400:400:400:400:400:400:400:400:400:400:404:404:400:400:400:400:400:404:+++:fnord/1.8+::fnord/1.8 [unconfigured]
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:501:404:501:200:404::^$:Fortinet SSL VPN website [Fortinet 310B software version 3.0 MR6]
+++:HTM:200:200:200:400:200:HTM:HTM:400:400:400:400:400:400:400:400:400:200:+++::^$:FortiGate firewall web management
+++:200:405:200:200:405:405:405:405:404:404:200:400:405:405:405:405:405:400:+++:::Foundry Networks/2.20
# Fred 0.5 (build 5076) HTTP Servlets
# Fred 0.5 (build 5105) HTTP Servlets
+++:400:200:302:400:302:400:400:400:302:302:302:---:404:404:404:404:404:404:+++::^Fred 0\.5 \(build 5[0-9]{3}\) HTTP Servlets$:Fred 0.5 (build 5xxx) HTTP Servlets [Freenet]
+++:404:404:200:200:200:404:404:404:200:404:200:404:404:404:404:404:404:404:+++::^$:FTGate
#
---:---:200:505:505:505:---:---:---:400:400:400:404:403:403:200:501:501:200:404:::Sun GlassFish Enterprise Server v2.1
# Windows Server 2008 64bit SP1 - Sun Java System Portal Server 7.2 - X-Powered-By: Servlet/2.5
---:---:200:505:505:505:---:---:---:400:400:400:404:403:403:200:501:501:200:---:::Sun Java System Application Server 9.1_01
#
200:200:400:200:200:400:200:400:400:400:500:200:---:400:400:400:400:400:500:---:::GoAhead-Webs [Orange Web Server]
+++:302:400:302:302:400:302:400:400:400:500:302:---:400:400:400:400:400:500:+++:::GoAhead-Webs [version 2.1, pre-compiled for Windows]
+++:302:400:302:302:400:302:400:400:302:500:302:---:400:400:400:400:400:302:+++:::GoAhead-Webs [version 2.1.8]
302:302:400:302:302:400:302:400:400:302:500:302:---:400:400:400:400:400:302:---:::GoAhead-Webs
# Gordano (installed by Messaging Suite)
+++:200:---:200:200:200:200:200:200:---:+++:+++:200:200:200:200:200:200:+++:+++:::Gordano Web Server v5.06.0016
+++:200:400:200:200:200:501:501:501:400:+++:+++:302:501:501:501:501:501:+++:+++:::Gordano Messaging Suite Web Server v9.01.3158
+++:---:---:---:---:302:---:---:---:200:200:302:411:---:---:---:---:---:200:+++:::GWS/2.1
# HP JetDirect 600N (J3110A)
# Version: ROM G.08.08, EPROM G.08.20
+++:HTM:404:xxx:xxx:xxx:xxx:xxx:xxx:404:404:200:404:404:404:404:404:404:+++:+++::HTTP/1\.0:HP JetDirect 600N (J3110A)
+++:xxx:200:200:200:501:200:HTM:xxx:200:+++:400:404:405:405:200:405:501:+++:+++:::HP Web Jetadmin/2.0.39 (Win32) mod_ssl/2.0.39 OpenSSL/0.9.6c
# HP JetDirect 600N (J3113A) with latest firmware (G.08.49)
# Probably the same signature as above; the HTML identification code changed recently
+++:HTM:404:HTM:HTM:HTM:xxx:xxx:xxx:404:404:200:404:404:404:404:404:404:+++:+++::HTTP/1\.0:HP JetDirect 600N (J3113A) with G.08.49 firmware
# Two signatures from HP RX 2600
+++:HTM:501:200:HTM:HTM:200:HTM:HTM:404:+++:200:501:501:501:501:501:501:+++:+++::^$:HP Web Console [HP RX 2600]
+++:HTM:501:200:---:---:---:---:---:---:+++:---:---:---:---:---:---:---:+++:+++::^$:HP Web Console [HP RX 2600]
+++:200:405:200:200:405:405:405:200:200:200:200:+++:404:405:405:405:405:+++:+++::^$:MarkNet / HP Laserjet printer
#
+++:---:---:---:---:---:---:---:---:404:404:200:404:404:---:---:---:---:404:+++::^eHTTP v1\.0:HP ProCurve Switch 2524 J4813A release #F.05.17
+++:505:---:505:505:---:---:---:200:404:404:200:---:---:---:---:---:---:+++:+++::^EHTTP/1\.1:HP J4121A ProCurve Switch 4000M Firmware revision C.09.19
+++:HTM:HTM:200:HTM:HTM:200:HTM:200:200:200:200:200:200:200:HTM:HTM:HTM:200:+++:::Motive Chorus (HP Instant Support Enterprise Edition)
#
+++:200:400:200:200:400:200:400:400:200:200:200:200:400:400:400:400:400:200:+++::^$:HTTP::Server::Simple [unconfigured Perl module]
# dev-util/qmtest-2.4.1
---:---:501:HTM:HTM:HTM:302:HTM:HTM:404:301:302:400:501:501:501:501:501:404:404:::SimpleHTTP/0.6 Python/2.7.1
# httpdx 0.3 beta [X-Powered-By: PHP/5.2.9-1]
# httpdx 0.4 beta [X-Powered-By: PHP/5.2.9-1]
400:400:400:200:400:400:400:400:400:400:400:400:---:400:400:400:400:400:400:400:httpdx:^httpdx 0\.[3-5] beta:httpdx 0.3-0.5 beta
# HFS 2.2a	# HFS 2.2d	# HFS 2.2f
200:200:---:200:200:200:---:---:---:400:400:200:---:---:---:---:---:---:404:404:::HFS 2.2
# See http://www.rejetto.com/hfs/
200:200:---:200:200:200:---:---:---:400:400:200:404:---:---:---:---:---:404:404:::HFS 2.3 beta
200:200:405:200:200:200:405:405:405:400:400:200:404:405:405:405:405:405:404:404:::HFS 2.3 beta
+++:200:501:200:200:501:200:---:---:200:200:200:404:500:501:501:501:501:404:+++:::Hyperwave-Information-Server/5.5
+++:200:200:200:200:501:200:---:---:200:200:200:404:401:404:500:400:500:404:+++:::Hyperwave-Information-Server/5.5
+++:200:501:200:200:501:200:---:---:200:200:200:404:400:501:501:501:501:200:+++:::Hyperwave-IS/6
# A Polish server, it seems. Can anybody provide details?
+++:HTM:---:200:200:400:200:---:---:---:---:400:404:400:400:400:400:400:200:+++:::IdeaWebServer/v0.21
+++:XML:---:200:200:400:200:---:---:---:---:400:404:400:400:400:400:400:200:+++:::IdeaWebServer/v0.21
+++:HTM:---:200:200:400:200:---:---:---:---:400:302:400:400:400:400:400:200:+++:::IdeaWebServer/v0.21
+++:---:---:200:200:400:200:---:---:---:---:400:404:400:400:400:400:400:200:+++:::IdeaWebServer/v0.21
#
+++:HTM:404:VER:VER:VER:200:HTM:HTM:200:404:400:+++:404:404:404:404:404:+++:+++:::IMV Web Server v1.0
+++:200:---:200:200:200:---:---:---:200:404:200:---:---:---:---:---:---:404:+++:Indy/8::Indy/8.0.25 [www.minihttpserver.net]
+++:404:---:200:200:200:---:---:---:200:404:200:---:---:---:---:---:---:404:+++:Indy/9::Indy/9.0.11
+++:404:---:404:404:404:---:---:---:404:200:404:+++:---:---:---:---:---:+++:+++:Indy/9::Indy/9.00.10
# More precise
404:404:---:404:404:404:---:---:---:404:200:404:---:---:---:---:---:---:404:404:Indy/9::Indy/9.00.10
# PRTG Traffic Grapher V4.3.1.562 Prof. Edition   2004-2005 Paessler GmbH
200:200:---:200:200:200:---:---:---:200:200:200:+++:---:---:---:---:---:+++:+++:Indy/9::Indy/9.0.11 [might be PRTG Traffic Grapher V4.3.1.562]
# Same, raw signature
401:401:---:401:401:401:---:---:---:401:401:401:+++:---:---:---:---:---:+++:+++:Indy/9::Indy/9.0.11 [might be PRTG Traffic Grapher V4.3.1.562]
# More precise
# Indy/9.00.10	# Indy/9.0.11
200:200:---:200:200:200:---:---:---:200:200:200:---:---:---:---:---:---:200:200:Indy/9:^Indy/9\.0+\.1[01]:Indy/9.0.10-9.0.11
# Ingrian management console (typically on 9443/tcp)
404:400:501:404:404:404:404:400:400:400:400:404:+++:501:501:501:501:501:+++:+++:Ingrian:^$:Ingrian i321 [Ingrian OS 4.4.2 patch 6]
#
+++:HTM:500:HTM:HTM:505:HTM:HTM:HTM:200:+++:200:500:500:500:500:500:500:+++:+++:::Inktomi Search 4.2.0
# Internet Anywhere Admin Server (v.2.1-5.3?)
+++:200:400:200:200:200:200:200:200:200:VER:200:400:400:400:400:400:400:200:+++:::Internet Anywhere WebServer [v2.1]
# Ipswitch
+++:VER:501:VER:VER:VER:501:501:501:200:404:400:---:501:501:501:501:501:200:+++:::Ipswitch-IMail/8.02
# More precise & conflicting
VER:VER:501:VER:VER:VER:501:501:501:200:404:400:---:501:501:501:501:501:200:---:::Ipswitch-IMail/8.22
# Ipswitch older (obsolete?) signatures
+++:HTM:501:HTM:HTM:HTM:501:501:501:200:404:400:---:501:501:501:501:501:+++:+++::Ipswitch:Ipswitch Web Calendaring /8.04 or Ipswitch-IMail/8.04
+++:200:---:200:200:404:---:---:---:200:200:200:---:---:---:---:---:---:+++:+++:::IMail_Monitor/8.04
# Conflicting & more precise
404:200:---:200:200:404:---:---:---:200:200:200:---:---:---:---:---:---:200:404:::IMail_Monitor/7.15
200:200:---:200:200:404:---:---:---:200:200:200:---:---:---:---:---:---:404:---:WhatsUpServer:^WhatsUpServer. Ipswitch 1.0:WhatsUpServer: Ipswitch 1.0 [WhatsUpGold 1.1]
+++:400:405:400:400:400:200:400:200:200:+++:400:404:405:405:405:405:405:+++:+++:::Intel NMS 1.0
+++:xxx:---:200:200:---:---:---:---:404:200:200:404:---:---:---:---:---:+++:+++:::IP_SHARER WEB 1.0 [Netgear Wireless router, WGR-614]
+++:xxx:---:200:200:---:200:---:---:404:200:200:404:---:---:---:---:---:200:+++:::IP_SHARER WEB 1.0
# Version R14.2.15-3 (April 23rd, 1998). Debug level set to 0.
# 0 child process(es) active out of a maximum of 25.
# from Annex Corporation for a Xylogic serial annex server running on HP-UX.
+++:200:---:200:200:---:200:200:200:200:---:200:---:---:---:---:---:---:200:+++::^$:Security/boot server
+++:500:501:200:200:405:500:500:500:200:200:200:404:405:405:405:405:405:200:+++:::Servertec-IWS/1.11
# SimpleHTTP from http://www.iki.fi/iki/src/index.html
+++:HTM:HTM:HTM:HTM:302:302:HTM:HTM:404:404:302:404:HTM:HTM:HTM:HTM:HTM:404:+++:::SimpleHTTP/1.2
200:200:---:200:---:---:200:---:---:200:---:200:400:400:400:400:400:400:200:200::^$:ejabberd web administration
# Jana is seriously broken: it answers 200 to all requests. The real code is in the returned page, which is not HTTP conformant
# no404 partly fixes the signature.
+++:200:200:200:200:200:200:200:200:200:200:200:404:404:404:404:404:404:404:+++:::Jana-Server/2.4.2
# Oracle?
+++:HTM:200:505:400:501:400:HTM:400:400:+++:400:404:403:403:200:501:501:+++:+++:::JavaWebServer/2.0
+++:404:501:404:404:501:404:501:400:404:+++:404:501:501:501:501:501:501:+++:+++:::Java Cell Server
+++:400:400:200:200:400:400:400:400:400:400:200:400:400:400:400:400:400:+++:+++::^$:JDMK4.1/Java2 Agent view on Windows 2000
# Jetty - I got the same sig for two versions
# Jetty/5.0.alpha3 (Linux/2.4.20-gentoo-r8 i386 java/1.4.1)
# Jetty/4.2.14 (Linux/2.4.20-gentoo-r8 i386 java/1.4.1)
+++:HTM:200:200:200:200:---:---:---:404:+++:+++:404:404:404:200:404:404:200:+++:Jetty/4 or Jetty/5:Jetty/[45]\.:Jetty 4.2 or 5.0alpha
# JBoss (default installation, w/ no200)
+++:HTM:200:200:200:200:---:---:---:404:+++:+++:100:100:404:200:405:405:404:+++:Jetty/4:Jetty/4\.:Jetty 4.2 in JBoss 3.0.6 (out of the box)
# also Jetty/4.2.9 (Windows 2000/5.0 x86 java/1.4.2)
+++:HTM:200:200:200:200:---:---:---:404:+++:+++:404:404:404:200:405:405:404:+++:Jetty/4:Jetty/4\.:Jetty 4.2 in JBoss 3.2.1 (out of the box) or Jetty/4.2.9
+++:xxx:200:503:503:500:200:HTM:xxx:400:400:400:200:200:200:200:200:200:200:+++:Jetty/4::Jetty/4.2.11 (Linux/2.4.20-8smp x86 java/1.4.1)
+++:HTM:404:200:200:200:---:---:---:404:+++:400:100:100:404:200:404:404:+++:+++:Jetty/4::Jetty/4.1.4 (Windows XP 5.1 x86)
+++:HTM:404:200:200:200:---:---:---:302:400:400:404:404:404:200:404:404:200:+++:Jetty/4::Jetty/4.2.9 (Windows 2003/5.2 x86 java/1.4.2_04)
#
+++:HTM:200:200:HTM:501:200:---:---:404:+++:---:404:404:404:404:404:404:200:+++:Jigsaw/1:1\.0beta:Jigsaw 1.0beta2
+++:HTM:200:200:HTM:501:200:---:---:404:+++:400:404:404:404:404:404:404:200:+++:Jigsaw/2::Jigsaw/2.0.5
+++:HTM:200:200:HTM:501:200:---:---:404:+++:+++:404:404:404:200:404:404:200:+++:Jigsaw/2::Jigsaw/2.2.2
# More precise
+++:HTM:200:200:HTM:501:200:---:---:404:404:400:404:404:404:200:404:404:200:+++:Jigsaw/2.2:^Jigsaw/2\.2\.[45]:Jigsaw/2.2.4-5
+++:HTM:200:200:HTM:501:200:---:---:404:404:400:+++:400:404:200:404:404:+++:+++:Jigsaw/2.2::Jigsaw/2.2.4 [on Windows 2003 SP1]
+++:400:200:200:400:400:400:400:400:400:400:404:405:200:200:200:200:200:404:+++:Jigsaw/2.2::Jigsaw 2.2.1 (Windows 2000)
+++:400:404:200:400:400:400:400:400:400:400:404:405:404:404:404:404:404:404:+++:Jigsaw/2.2::Jigsaw 2.2.1(windows 2000)
+++:HTM:200:200:HTM:501:301:---:---:301:301:400:404:404:404:200:404:404:301:+++:Jigsaw/2.2::Jigsaw/2.2.4
+++:XML:200:200:XML:501:200:---:---:404:404:400:404:404:404:200:404:404:200:+++:Jigsaw/2.2::Jigsaw/2.2.5
# OS: Solaris 8 07/03 HW release, kernel patch 108528-27
# Web Server: Bundled with HP OpenView Performance Insight Version 4.6.0 GA, Service Pack 1
+++:---:302:200:200:200:---:---:---:302:302:200:404:501:501:501:501:501:+++:+++:::JRun Web Server
# Kazaa - not a real web server
+++:501:---:404:404:---:501:501:501:501:501:404:501:501:---:---:---:---:404:+++::^$:Kazaa servent (not a real web server)
# Candle Web Server (Omegamon is a supervision/monitoring software)
# KDH/185.4 (v180_kbs4054a)
# KDH/185.4 (v180_kbs3348a)
# and also KDH/185.67?
+++:---:404:---:---:200:200:---:---:404:404:200:404:404:404:404:---:---:200:+++:::KDH/185.4 [Candle Web Server from Omegamon]
# Less precise
# KDH/185.67 (v180_kbs4190a)
+++:---:404:---:---:200:200:---:---:404:404:200:+++:404:404:404:---:---:+++:+++:::KDH/185 [Candle Web Server from Omegamon]
# Kerio Personal Firewall
# Sunbelt Personal Firewall (new name of Kerio)
---:---:---:200:200:---:---:---:---:200:---:200:---:---:---:---:---:---:200:200::^(Kerio|Sunbelt) Personal Firewall:Kerio Personal Firewall
+++:---:501:---:---:200:---:---:---:301:403:200:404:501:501:501:---:---:403:+++:KFWebServer:^KFWebServer/2\.5\.0 Windows:KFWebServer/2.5.0 on Windows 98 or NT4
# More precise but conflicting
---:---:501:---:---:200:---:---:---:301:403:200:404:501:501:501:---:---:403:403:KFWebServer::KFWebServer/3.2.0 Windows XP
# knobot-standalone-self-extracting-0.2.14.jar
+++:XML:200:200:500:500:---:---:---:500:400:400:500:401:302:200:200:200:500:+++:::WYMIWYG RWCF (the KnoBot foundation) 0.3
# Lacie Ethernet Disk 250gb (NAS)
# Package version              2.0
# Software version             LaCix - 1.3.4
# Operating system             Linux Embedded - 2.4.25-lacie6
# Bios version                 U-Boot 1.1.1
# Manufacturer and model       LaCie Group, S.A.
# Physical memory              59 MB
# Virtual memory               125 MB
# Windows File Server          Running
# Apple File Server            Stopped
# FTP service                  Running
# HTTP service                 Running
# Bonjour service              Stopped
200:200:501:200:200:200:404:400:400:400:501:200:501:501:501:501:501:501:200:404:Lacie-NAS:^$:Lacie Ethernet Disk 250gb (NAS)
# Linksys WRV54G wireless G router (with VPN)
# Hardware Version:  	   Rev.02
# Software Version: 	   2.37.1
+++:HTM:501:200:400:200:200:400:400:400:400:400:400:501:501:501:501:501:+++:+++::^$:Linksys WRV54G wireless router
401:---:---:401:401:401:---:---:---:400:---:401:404:---:---:---:---:---:400:404::^httpd$:Linksys WRT54G
+++:HTM:400:200:200:200:200:400:400:400:400:200:404:400:400:400:400:400:HTM:+++:::LiteWeb/1.21
# LiteWeb/2.3
# LiteWeb/2.5
+++:200:200:302:200:200:200:200:200:200:200:200:---:200:200:200:200:200:200:+++:::LiteWeb/2.
403:403:302:505:403:---:---:---:403:403:403:400:302:302:302:---:---:---:403:403:LogmeIn:^$:LogMeIn 4.0.762
# Lotus Domino
+++:HTM:200:200:200:200:200:HTM:HTM:200:+++:400:500:405:405:200:501:501:+++:+++:Lotus-Domino/4.6::Lotus-Domino/4.6
+++:HTM:200:200:200:404:404:HTM:HTM:200:403:400:500:405:405:200:501:501:404:+++:Lotus-Domino/4.6::Lotus-Domino/Release-4.6.5
+++:HTM:---:200:200:200:200:HTM:HTM:403:500:400:500:405:405:405:501:501:403:+++:Lotus-Domino/5.0::Lotus-Domino/5.0.5
+++:HTM:405:200:200:200:200:HTM:HTM:403:500:400:500:405:405:405:501:501:500:+++:Lotus-Domino/5.0::Lotus-Domino/5.0.8
+++:HTM:405:200:200:200:200:HTM:HTM:200:500:400:500:405:405:405:501:501:404:+++:Lotus-Domino/5.0::Lotus-Domino/5.0.3
# Lotus-Domino/5.0.8
# Lotus-Domino/0
+++:HTM:405:200:200:200:200:HTM:HTM:200:500:400:500:405:405:405:501:501:500:+++:Lotus-Domino/5.0:^Lotus-Domino/(0|5\.0\.([89]|1[0-2]))$:Lotus Domino 5.0.8-12 [on Windows 2000 SP4 w/ AD?]
+++:400:200:200:400:200:200:400:400:200:200:400:404:404:404:200:404:405:+++:+++:Lotus-Domino/6.5:^Lotus-Domino$:Lotus-Domino/R6.5
# Lotus Domino 6.5.1 for Win32 with interim fix 1 & spanish language pack installed in replace mode
+++:400:200:200:400:200:200:400:400:200:200:400:404:405:405:200:405:405:200:+++:Lotus-Domino/6.5:^Lotus-Domino$:Lotus-Domino/R6.5.1IF1
# Domino-Go-Webserver/4.6.2.2
# Domino-Go-Webserver/4.6.2.51
+++:HTM:200:200:200:HTM:200:HTM:HTM:200:403:400:500:405:405:200:501:501:404:+++:::Domino-Go-Webserver/4.6.2.
+++:HTM:200:200:200:200:200:HTM:HTM:403:403:400:500:405:405:200:501:501:404:+++:::Domino-Go-Webserver/4.6.2.5
+++:400:200:200:400:200:200:400:400:200:200:400:404:405:405:200:405:405:+++:+++:Lotus-Domino/6.5:^Lotus-Domino:Lotus-Domino/6.5.1 on Linux
#
+++:200:501:200:200:501:404:404:404:404:404:200:---:501:501:501:501:501:404:+++:::EPSON-HTTP/1.0
+++:HTM:501:200:HTM:200:200:HTM:200:302:+++:200:404:501:501:501:501:501:+++:+++:::LV_HTTP/1.0
+++:HTM:---:200:---:---:200:---:200:200:+++:200:---:---:---:---:---:---:+++:+++:::LabVIEW/7.0
+++:400:501:400:400:501:400:400:400:404:301:400:411:501:501:501:501:501:200:+++:lighttpd/1.3::lighttpd/1.3.5 (Nov  3 2004/13:06:27)
400:400:200:400:400:501:400:400:400:404:200:400:411:501:501:501:501:501:200:404:lighttpd/1.3::lighttpd/1.3.16
+++:400:501:400:400:501:400:400:400:400:301:400:411:501:501:501:501:501:200:+++:lighttpd/1.3:lighttpd/1\.3\.1[01]:lighttpd/1.3.10-11
+++:400:501:400:400:501:400:400:400:400:200:400:411:501:501:501:501:501:200:+++:lighttpd/1.3:lighttpd/1\.3\.1[23]:lighttpd/1.3.12-13
+++:400:200:400:400:501:400:400:400:404:200:400:411:404:404:501:501:501:200:+++:lighttpd/1.4::lighttpd/1.4.0
# lighttpd/1.4.11	# lighttpd/1.4.13
# lighttpd/1.4.15 (including Gentoo 1.4.15-r1)	# lighttpd/1.4.16
# lighttpd/1.4.18	# lighttpd/1.4.19	# lighttpd/1.4.20
# lighttpd/1.4.22	# lighttpd/1.4.25	# lighttpd/1.4.26
# lighttpd/1.4.28	# lighttpd/1.4.30
400:400:200:505:400:501:400:400:400:404:200:400:411:404:404:501:404:501:200:404:lighttpd/1.4:lighttpd/1\.4\.(1[1-9]|2[0-9]|3[0-2]):lighttpd/1.4.11-32
400:400:200:505:400:501:400:400:400:404:200:400:411:404:404:404:404:404:200:404:::lighttpd/1.4.35
# The banner is only: lighttpd
+++:400:200:400:400:501:400:400:400:404:200:400:411:404:404:501:404:501:200:+++:lighttpd/1.4::lighttpd/1.4.1
+++:404:500:200:200:200:401:401:401:404:500:200:---:500:500:500:500:500:+++:+++::^$:Linksys BEFW11S4 WAP - 1.44.2z, Dec 13 2002
+++:200:501:200:200:400:400:400:400:404:+++:200:501:501:501:501:501:501:+++:+++:::LseriesWeb/1.0-beta (LSERIES)
+++:HTM:HTM:HTM:HTM:HTM:302:HTM:HTM:HTM:---:HTM:404:HTM:HTM:HTM:HTM:HTM:404:+++:::LWS 0.1.2 [unconfigured]
xxx:xxx:404:HTM:HTM:HTM:404:HTM:HTM:404:400:404:200:200:200:200:200:200:404:404:::PasteWSGIServer/0.5 Python/2.7.2 [Firefox sync server]
+++:200:400:200:200:200:400:400:400:400:+++:200:404:401:400:400:400:400:+++:+++:::PersonalNetFinder/1.0 ID/ACGI
# PersonalNetFinder/1.0 ID/ACGI
# MACOS_Personal_Websharing
+++:200:400:200:200:200:400:400:400:400:+++:200:404:403:400:400:400:400:+++:+++::MACOS_Personal_Websharing|PersonalNetFinder:MacOS PersonalNetFinder
+++:HTM:HTM:200:---:HTM:200:HTM:HTM:HTM:+++:400:200:HTM:HTM:HTM:HTM:HTM:+++:+++:::AppleShareIP/6.0.0
+++:HTM:HTM:200:---:HTM:200:HTM:HTM:HTM:---:400:404:HTM:HTM:HTM:HTM:HTM:HTM:+++:::AppleShareIP/6.3.2
#
+++:HTM:501:xxx:HTM:HTM:200:HTM:HTM:404:301:400:404:501:501:501:501:501:200:+++:::HTTPi/1.4 (xinetd/Linux)
+++:HTM:501:400:400:501:404:---:---:400:400:404:404:501:501:501:501:501:400:+++:::Mathopd/1.4p1
+++:---:501:505:400:---:400:---:---:400:400:400:411:501:501:501:501:501:414:+++:::Mathopd/1.5b11
+++:200:400:200:200:501:400:400:400:200:400:200:404:404:404:404:404:404:+++:+++:::Mdaemon Worldclient 2.06
# Conflicting & unconfirmed
# WDaemon/3.0
# WDaemon/4.0
200:200:400:200:200:501:400:400:400:200:400:200:404:404:404:404:404:404:403:404:wdaemon:^$:WDaemon/3.0-4.0
# MediabolicMWEB/1.0
# MediabolicMWEB/1.2
400:400:404:400:400:400:400:400:400:404:404:404:404:404:404:404:404:404:404:404:MediabolicMWEB/1:^MediabolicMWEB/1\.[02]:MediabolicMWEB/1.0-1.2
# MERCUR Messaging 2005 version 5.0 (SP2) / 5.0.10.0
+++:404:404:200:200:200:404:404:404:200:404:200:404:404:404:404:404:404:200:+++:::MERCUR Messaging 2005 [version 5.0 (SP2) / 5.0.10.0]
+++:VER:VER:VER:VER:VER:VER:---:---:VER:VER:VER:VER:VER:VER:VER:VER:VER:VER:+++::^$:msfweb [Metasploit framework 2.5]
---:---:501:VER:VER:---:---:---:---:404:200:200:501:501:501:501:501:501:404:404:::mghttpd
# Snap Appliance, Inc./3.4.803
# Meridian Data/2.3.417
+++:400:501:200:200:xxx:400:400:400:200:200:200:200:501:501:501:501:501:+++:+++::^(Snap Appliance|Meridian Data):Quantum Snap Server
# model: 4000 series / OS: 3.4.790 (US) / Hardware: 2.2.1 / BIOS: 2.4.437
+++:400:501:200:200:HTM:400:400:400:404:200:200:404:501:501:501:501:501:400:+++:::Quantum Corporation./3.4.790
# Quantum Corporation./3.4.790
# Snap Appliances, Inc./3.1.618
+++:400:501:200:200:HTM:400:400:400:200:200:200:404:501:501:501:501:501:400:+++::^(Snap Appliance|Quantum Corporation):Quantum Snap Server
# Belkin 54g Wireless AP model F5D7130 - version 1000
# micro_httpd_14dec2001 or micro_httpd_12dec2005
400:400:501:200:200:200:400:400:400:400:501:200:501:501:501:501:501:501:400:404:::micro_httpd
+++:---:501:200:200:200:---:---:---:400:501:200:404:501:501:501:501:501:+++:+++:::micro_httpd
---:---:501:200:200:200:---:---:---:400:501:200:404:501:501:501:501:501:400:404:::micro_httpd
+++:HTM:400:200:200:400:400:400:400:404:+++:200:400:501:501:400:400:501:+++:+++:::Micro-HTTP/1.0
+++:HTM:501:200:200:501:400:400:400:404:+++:200:400:501:501:501:501:501:+++:+++:::Micro-HTTP/1.0
+++:HTM:501:200:200:501:400:400:400:404:+++:200:400:501:501:501:501:HTM:+++:+++:::Micro-HTTP/1.0
+++:HTM:501:200:200:HTM:400:400:400:404:+++:200:400:HTM:501:HTM:HTM:HTM:+++:+++:::Micro-HTTP/1.0
+++:HTM:501:200:200:501:400:400:400:404:+++:200:400:HTM:501:HTM:HTM:501:+++:+++:::Micro-HTTP/1.0
+++:HTM:HTM:200:200:HTM:400:400:400:404:+++:200:400:HTM:HTM:501:501:HTM:+++:+++:::Micro-HTTP/1.0
# Sophos PureMessage w/ Apache 2.2.8
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:---:405:501:200:---::^Apache\/2\.2\.8 \(Unix\).+ Perl\/v5\.8\.7:Apache/2.2.8 (Unix) mod_ssl/2.2.8 OpenSSL/0.9.8k mod_perl/2.0.1 Perl/v5.8.7
# Symantec Gateway Security 320
# Firmware version : 2.1.0 Build 1336
# On Linux, default config
200:404:501:200:200:200:404:501:400:400:501:200:---:501:501:501:501:501:401:---:::Micro-Web [Symantec Gateway Security 320]
# MS IIS
+++:HTM:404:200:HTM:501:200:400:400:200:404:200:501:501:501:501:501:501:200:+++::^Microsoft-IIS/[23]\.0:Microsoft-IIS/2 or Microsoft-IIS/3
# MS PWS (old sig)
##HTM:200:404:200:200:HTM:400:501:HTM:200:400:400:200:200:404:+++:200:501:501:501:501:501:501:501:+++:Microsoft-PWS/3.0
+++:200:200:200:200:400:400:400:400:400:400:400:405:403:403:200:501:501:200:+++::^Microsoft-IIS/4\.0:Microsoft-IIS/4 on Win98SE [PWS]
#
+++:HTM:200:200:HTM:400:400:400:400:400:+++:+++:405:411:404:200:501:501:+++:+++:::Microsoft-IIS/4.0
+++:HTM:200:200:HTM:404:400:400:400:400:400:400:405:404:404:404:404:404:200:+++:::Microsoft-IIS/4.0
+++:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:501:501:200:+++:::Microsoft-IIS/4.0 [on Windows NT4 SP6a, or MS PWS on Windows 98]
+++:404:501:200:200:501:200:501:---:---:501:200:405:501:501:501:501:501:200:+++:::Microsoft-IIS/5.0 [on Windows Server 2003 SP 1]
+++:404:200:200:404:400:400:400:400:400:+++:+++:405:501:501:200:501:501:+++:+++:::Microsoft-IIS/5.0
+++:404:200:200:404:400:400:400:400:400:+++:404:405:411:404:200:400:411:+++:+++:::Microsoft-IIS/5.0
+++:200:200:200:200:400:400:400:400:400:400:400:405:501:501:200:501:501:200:+++:::Microsoft-IIS/5.0
+++:HTM:200:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:200:+++:::Microsoft-IIS/5.0
+++:200:404:VER:200:400:400:400:400:400:400:400:405:404:404:404:404:404:200:+++:::Microsoft-IIS/5.0 [Using iHTML/2.20.8]
## Might be IIS-4 or IIS-5?? I don't like that. I suspect I was given wrong information
# IIS-5 w/ ASP.net
+++:200:404:200:200:400:400:400:400:400:400:400:405:404:404:404:404:404:200:+++:::Microsoft-IIS/5.0
# Same as above, imprecise
# X-Powered-By: ASP.NET - X-Powered-By: PHP/4.3.2
+++:200:404:200:200:400:400:400:400:400:400:400:405:404:404:404:404:404:+++:+++:::Microsoft-IIS/5.1
# w/ PHP and ASP.NET?
+++:404:200:200:404:400:400:400:400:400:400:404:405:403:403:200:400:411:404:+++:::Microsoft-IIS/5.0
+++:200:200:200:200:400:400:400:400:400:400:200:200:403:403:200:403:403:200:+++:::Microsoft-IIS/5.0 w/ ASP.NET
+++:HTM:200:200:HTM:400:400:400:400:400:+++:400:405:411:404:200:400:411:+++:+++:::Microsoft-IIS/5.0
# Somebody got the same signature w/ URLScan
+++:200:200:200:200:400:400:400:400:400:400:400:200:200:200:200:200:200:+++:+++::^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 [Windows 2000 server SP4 w/ latest patches (2003-02-05)]
+++:403:200:200:403:400:400:400:400:400:400:400:405:501:501:200:501:501:403:+++::^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 [Windows 2000 SP3 w/ iislockdown & urlscan]
# Suspicious signature
+++:404:404:200:404:400:400:400:400:400:400:404:405:404:404:404:404:404:404:+++::Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [w/ URLScan 2.5 (6.0.3615.0) on Win2000 server up to date (2004-01-14)]
# Windows 2000 server SP4 w/ urlscan, w/o OWA
+++:HTM:404:200:HTM:400:400:400:400:400:400:400:404:404:404:404:404:404:+++:+++::Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [w/ UrlScan, w/o Outlook Web Access, on Win2000 SP4]
#
# MS IIS 5.0 with UrlScan allowing all ASP pages, without Outlook Web Access, on Win2000 SP4
# or:
# Windows 2000 Server 5.0.2195 Service Pack 4 Build 2195
# Microsoft Exchange Server Version 5.5 (Build 2653.23: Service Pack 4)
# UrlScan with Outlook Web Access
#
+++:HTM:404:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:+++:+++::^Microsoft-IIS/5\.0$:Microsoft-IIS/5.0 [w/ UrlScan]
# Windows 2000, SP3? 4? w/o the latest patches
#200:200:400:200:200:200:400:400:400:400:400:400:200:400:400:400:400:405:403:403:200:200:400:411:+++:Microsoft-IIS/5.0
# More precise
+++:200:400:200:200:400:400:400:400:400:400:400:405:403:403:200:400:411:200:+++:::Microsoft-IIS/5.0
# X-Powered-By: ASP.NET
# Windows 2000 Advanced Server, SP-4 Build 2195; IIS5 with .NET
+++:200:200:200:200:400:400:400:400:400:400:400:405:403:403:404:400:411:+++:+++::Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [w/ .NET on Win2000 SP4]
+++:200:200:200:200:400:400:400:400:400:400:400:405:403:403:200:400:411:200:+++:Microsoft-IIS/5.0 or Microsoft-IIS/5.1:^Microsoft-IIS/5\.[01]:Microsoft-IIS/5.0 on Win2000 SP4 or Microsoft-IIS/5.1 on WinXP SP1
# IIS 5.0 on Win 2000 SP4 server english with all patches (2003-12-16) & .NET & without Lockdown
+++:xxx:200:200:xxx:400:400:400:400:400:400:400:405:403:403:200:400:411:+++:+++::^Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [w/ .NET on Win2000 SP4]
+++:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:404:400:411:404:+++:::Microsoft-IIS/5.0
+++:HTM:200:200:HTM:400:400:400:400:400:400:400:405:501:501:200:501:501:200:+++:::Microsoft-IIS/5.0
+++:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:400:411:200:+++::^Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [on Win2000 w/ latest patches (2003-12-29)]
#+++:200:200:200:200:400:400:400:400:400:400:400:405:411:404:200:400:411:200:+++:::Microsoft-IIS/5.0
# next sig might be 5.1 too??
200:200:200:200:200:400:400:400:400:400:400:400:405:411:404:200:400:411:200:414:::Microsoft-IIS/5.0
+++:HTM:500:200:HTM:400:400:400:400:400:+++:400:405:500:500:200:500:500:+++:+++:::Microsoft-IIS/5.1
# Microsoft-IIS/5.0
# Microsoft-IIS/5.1 [w/ ASP.NET]
200:200:200:200:200:400:400:400:400:400:400:400:405:403:403:200:400:411:200:414:Microsoft-IIS/5.0 or Microsoft-IIS/5.1:Microsoft-IIS/5\.[01]:Microsoft-IIS/5.0-5.1
+++:200:500:200:200:400:400:400:400:400:400:400:405:500:500:200:500:500:200:+++:::Microsoft-IIS/5.1
# IIS 5, Windows 2000 SP-4 running OWA on exchange 5.5
+++:400:404:200:400:400:400:400:400:400:400:400:405:404:404:404:404:404:200:+++::^$:Microsoft-IIS/5 (OWA on Exchange 5.5)
# Unpatched IIS 5.0 protected by Check Point Firewall-1 Smart Defense
+++:xxx:200:200:xxx:400:---:---:---:400:400:400:405:403:403:200:400:400:+++:+++::Microsoft-IIS/5\.0:Microsoft-IIS/5.0 [behind FW-1]
# IIS/6
+++:HTM:404:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:404:+++:::Microsoft-IIS/6.0 [on Windows 2003 SP1 w/ ASP.Net]
+++:HTM:200:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:+++:::Microsoft-IIS/6.0 [on Windows 2003 SP1 or SP2]
+++:HTM:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:411:200:+++:::Microsoft-IIS/6.0 [on Windows 2003 SP1]
+++:xxx:200:505:---:400:200:400:400:400:400:400:411:411:501:501:501:501:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET]
+++:HTM:---:505:400:400:200:400:400:400:400:400:411:411:403:501:400:411:200:+++:::Microsoft-IIS/6.0 [on Windows 2003 SP1 w/ ASP.NET]
+++:200:200:505:---:400:200:400:400:400:400:400:411:411:404:501:400:411:200:+++:::Microsoft-IIS/6.0
+++:HTM:---:505:400:400:200:400:400:400:400:400:411:411:---:501:400:411:200:+++:::Microsoft-IIS/6.0 [on Windows 2003 SP1 w/ ASP.NET]
+++:200:200:505:---:400:200:400:400:400:+++:400:411:411:403:501:400:411:+++:+++::Microsoft-IIS/6\.0:Microsoft-IIS/6.0 [w/ ASP.NET 1.1.4322]
+++:200:200:505:---:400:200:400:400:400:400:400:411:411:501:501:501:501:200:+++::^Microsoft-IIS/6\.0$:Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
+++:HTM:---:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
+++:HTM:200:505:---:400:200:400:400:400:400:400:411:411:403:501:400:411:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
HTM:HTM:200:505:---:400:200:400:400:400:400:400:411:411:403:501:400:411:200:400:::Microsoft-IIS/6.0 [on Windows 2003]
+++:HTM:200:505:400:400:200:400:400:400:400:400:411:411:404:501:400:411:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
+++:200:200:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003 SP1]
+++:200:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:411:200:+++:::Microsoft-IIS/6.0
+++:HTM:200:505:---:400:200:400:400:400:400:400:411:411:200:200:200:200:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
HTM:HTM:200:505:---:400:200:400:400:400:400:400:411:411:200:200:200:200:200:400:::Microsoft-IIS/6.0 [on Windows Server 2003 SP2]
+++:HTM:200:505:---:400:200:400:400:400:400:400:411:411:501:501:501:501:200:+++:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
# More precise
HTM:HTM:200:505:---:400:200:400:400:400:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0
# Windows 2003 + IIS6 and Citrix ICA portal
xxx:xxx:403:200:200:501:200:HTM:xxx:200:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0 [w/ ASP.NET on Windows 2003]
# IIS/7 w/ X-AspNet-Version: 2.0.50727
---:---:---:505:400:---:500:400:---:400:400:400:411:411:404:---:404:404:500:400:::Microsoft-IIS/7.0 [w/ ASP.NET on Windows 2008]
# MS ISA Server 2000
+++:400:500:403:400:400:403:400:400:500:500:403:403:403:403:403:403:403:403:+++::^$:MS ISA Server 2000 reverse proxy (rejecting connections)
# MS ISA 2004
+++:400:500:200:400:400:200:400:400:500:500:200:411:411:501:200:501:501:+++:+++:::Microsoft-IIS/6.0 [w/ .NET; through MS ISA Server 2004 Beta2]
#
400:HTM:503:200:400:503:200:400:400:400:400:200:501:501:503:503:503:503:200:404:mikrotik:^$:mikrotik routeros 3.4 webbox
# Mini HTTPD
+++:xxx:501:VER:VER:VER:200:xxx:xxx:400:400:200:404:501:501:501:501:501:400:+++:mini_httpd/1:mini_httpd/1\.1[78]:mini_httpd/1.17beta1 or 1.18
# Also ECL-WebAdmin/1.0 [Embedded Coyote Linux on Linux 2.4.23] from www.coyotelinux.com
+++:HTM:501:VER:VER:VER:200:HTM:HTM:400:400:200:404:501:501:501:501:501:400:+++:mini_httpd/1::mini_httpd/1.19 19dec2003
# Conflicting / more precise signature
# mini_httpd/1.18 26oct2003
# mini_httpd/1.19 19dec2003
HTM:HTM:501:VER:VER:VER:200:HTM:HTM:400:400:200:404:501:501:501:501:501:400:404:mini_httpd/1:mini_httpd/1\.1[89] [12][69][od][ce][tc]2003:mini_httpd/1.18 26oct2003 or mini_httpd/1.19 19dec2003
#
+++:400:400:400:400:400:200:400:400:200:+++:200:200:400:400:400:400:400:+++:+++:::MiniServ/0.01
+++:---:---:---:---:---:200:---:---:200:200:200:200:---:---:---:---:---:+++:+++:::MiniServ/0.01
# Webmin 1.340 on gentoo
+++:400:200:400:400:400:200:400:400:200:200:200:200:400:200:200:200:400:200:+++:::MiniServ/0.01 [Webmin 1.340]
#  app-admin/webmin-1.400-r1
---:---:200:---:---:---:200:---:---:200:200:200:200:400:200:200:200:400:200:200:::MiniServ/0.01 [Webmin 1.400]
200:---:200:200:200:200:---:---:---:200:200:200:200:200:200:200:200:200:200:200:::MLdonkey
# Monkey
#400:200:403:200:200:200:400:405:200:400:400:400:200:404:404:+++:+++:411:405:405:405:405:405:405:+++:Monkey/0:Monkey/0.7.1 (Linux)
# Same as above - more precise
+++:400:403:200:200:405:400:400:400:404:403:400:411:405:405:405:405:405:403:+++:Monkey/0::Monkey/0.8.2 (Linux)
+++:400:403:200:200:405:400:400:400:404:403:200:411:405:405:405:405:405:403:+++:Monkey/0::Monkey/0.9.1 (Linux)
# dev-dotnet/xsp-2.4.2 & dev-lang/mono-2.4.2.3
200:200:400:VER:VER:VER:500:500:500:200:200:200:405:405:405:405:405:405:200:404:::Mono.WebServer2/0.2.0.0 Unix
# Mono.WebServer2/0.2.0.0 Unix (dev-dotnet/xsp-2.8.2 & dev-lang/mono-2.8.2)
# Mono.WebServer2/0.2.0.0 Unix (dev-dotnet/xsp-2.6 & dev-lang/mono-2.6.3)
# Mono.WebServer/0.1.0.0 Unix  (dev-dotnet/xsp-2.6.5 & dev-lang/mono-2.6.7)
200:200:405:VER:VER:VER:500:500:500:200:200:200:405:405:405:405:405:405:200:404:xsp:^Mono\.WebServer2?/0\.[12]\.0\.0 Unix:Mono.WebServer Unix [dev-dotnet/xsp-2.6]
# MWS might be some DVR or Cisco ASDM 6.3(5) ?
200:404:---:200:200:---:404:404:404:404:---:200:---:---:---:---:---:---:200:200:::MWS/1.2.0
+++:302:501:302:302:302:302:501:302:404:401:302:404:401:401:501:501:501:400:+++:::MyServer 0.6.2
+++:302:200:302:302:302:302:200:200:200:200:302:---:---:401:200:200:200:302:+++:::MyServer 0.7
#
+++:---:---:200:---:---:---:---:---:---:---:---:404:404:404:404:---:---:+++:+++::PLT Scheme:mzserver 203-6 on Debian
+++:404:200:200:200:200:200:404:404:200:200:200:404:404:404:404:404:404:200:+++::^$:POW 0.0.9 [firefox extension]
# aEGiS_nanoweb/2.1.3 (Linux; PHP/4.3.3)
# aEGiS_nanoweb/2.2.0 (Linux; PHP/4.3.3)
# aEGiS_nanoweb/2.2.1 (Linux; PHP/4.3.3)
+++:200:200:200:200:501:501:501:200:404:404:200:404:501:501:501:501:501:200:+++::^aEGiS_nanoweb/2\.(1\.3)|(2\.[01]):aEGiS_nanoweb/2.1.3 or 2.2.0 or 2.2.1
+++:400:200:200:200:501:501:501:400:404:404:200:404:501:501:501:501:501:200:+++:::aEGiS_nanoweb/2.2.2 (Linux; PHP/4.3.3)
# Good old NCSA
+++:HTM:400:200:200:400:HTM:HTM:HTM:404:302:200:501:400:400:400:400:400:---:+++:::NCSA/1.1
# NCSA/1.2
# NCSA/1.4.2
+++:HTM:400:200:200:400:HTM:HTM:HTM:404:302:200:404:404:404:400:400:400:---:+++:NCSA/1.2+:^NCSA/1\.([234]):NCSA/1.2 to 4.2
+++:HTM:400:200:200:HTM:200:400:HTM:404:301:200:404:404:404:400:400:400:200:+++:NCSA/1.5+::NCSA/1.5
+++:HTM:HTM:HTM:HTM:HTM:200:HTM:400:404:+++:+++:404:404:404:400:400:400:+++:+++:NCSA/1.5+::NCSA/1.5.2
+++:HTM:400:HTM:HTM:400:200:HTM:400:404:+++:200:404:404:404:400:400:400:+++:+++:NCSA/1.5+::NCSA/1.5.2
+++:400:400:200:400:400:200:400:400:400:400:200:411:411:404:400:400:400:200:+++:NCSA/1.5+::NCSA/1.5.2 thru proxy cache
400:400:405:505:400:400:400:400:400:400:400:200:411:405:405:405:405:405:404:404:NessusWWW::NessusWWW
+++:200:---:200:200:200:---:---:200:404:---:200:+++:---:---:---:---:---:+++:+++:::Netgear
# http://www.geocities.com/SiliconValley/Platform/1297/misc/netchat.htm
+++:404:501:200:200:501:404:404:404:200:404:200:501:501:501:501:501:501:500:+++::^HTTPServer$:NetChat 7.4 on Windows 2000
200:200:501:200:200:501:404:404:404:200:501:200:401:501:501:501:501:501:---:401:::NetPort Software 1.1 [Polycom Video Teleconferencing Unit]
400:400:405:302:302:405:405:405:405:404:200:400:400:405:405:405:405:405:400:400:NetZoom::NetZoom/1.02 [Sony SNC-Z20 camera]
# Nofeel FTP Server Standard Edition Version 3.2.3342.0 running on XP SP2
+++:400:400:505:505:200:400:400:400:400:400:400:404:501:501:404:400:400:404:+++:::NofeelSoft-WebFTP/1.0
# nginx/0.1.24	# nginx/0.1.26	# nginx/0.1.28	# nginx/0.1.37	# nginx/0.1.41
# nginx/0.1.45	# nginx/0.2.6	# nginx/0.3.7	# nginx/0.3.9
+++:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:400:405:405:405:405:405:200:+++:nginx/0.1-0.3:^nginx/0\.[1-3]\.[0-9]+$:nginx/0.1.24-0.3.9
# nginx/0.3.61	# nginx/0.4.14	# nginx/0.5.22	# nginx/0.5.23	# nginx/0.5.24
# nginx/0.5.25	# nginx/0.6.0
+++:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:405:405:405:405:200:+++:nginx:^nginx/0\.[3-6]\.:nginx/0.3.61-0.6.0
# More precise
# nginx/0.5.25	# nginx/0.6.0	# nginx/0.6.1	# nginx/0.6.5	# nginx/0.6.8
# nginx/0.6.9	# nginx/0.6.10	# nginx/0.6.11	# nginx/0.6.13	# nginx/0.6.15
# nginx/0.6.16	# nginx/0.6.21	# nginx/0.6.24	# nginx/0.6.25	# nginx/0.6.29
# nginx/0.6.30	# nginx/0.7.2	# nginx/0.7.4	# nginx/0.7.5	# nginx/0.7.6
# nginx/0.7.8	# nginx/0.7.11	# nginx/0.7.13	# nginx/0.7.14	# nginx/0.7.16
# nginx/0.7.17	# nginx/0.7.19	# nginx/0.7.20	# nginx/0.7.21	# nginx/0.7.22
# nginx/0.7.24
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:405:405:405:405:200:HTM:nginx:^nginx/0\.[5-7]:nginx/0.5.25-0.7.24
# www-servers/nginx-0.7.26 pcre perl ssl zlib -addition -debug -fastcgi -flv -imap -status -sub -webdav
# nginx/0.7.30	# nginx/0.7.32	# nginx/0.7.33	# nginx/0.7.38	# nginx/0.7.39
# nginx/0.7.54	# nginx/0.7.55	# nginx/0.7.59	# nginx/0.8.2	# nginx/0.8.4
# nginx/0.8.8	# nginx/0.8.13	# nginx/0.8.16	# nginx/0.8.31	# nginx/0.8.34
# nginx/0.8.35	# nginx/0.8.36	# nginx/0.8.46	# nginx/0.8.48	# nginx/1.0.0
# nginx/1.0.6	# nginx/1.0.10	# nginx/1.2.1
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:404:411:405:405:405:405:200:HTM:nginx:^nginx/(1\.([01]\.([0-9]+)|2\.[01])|0\.(7\.(2[6-9]|[3-9][0-9])|8\.([0-9]|[1-3][0-9]|4[0-8])))$:nginx/0.7.26-1.2.1
# on Windows 32-bit...
# nginx/1.0.8   # nginx/1.013   # nginx/1.0.14
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:404:411:405:405:405:405:200:404:nginx:^nginx/1\.0\.(8|1[34])($|[^0-9.])::nginx/1.0.8-1.0.14
# nginx/0.8.9	nginx/0.8.10
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:405:411:405:405:405:405:200:HTM:nginx:^nginx/0\.8\.(9|10)$:nginx/0.8.9-0.8.10
# www-servers/nginx-0.3.35  -debug -fastcgi -imap +pcre -perl +ssl +threads* +zlib
+++:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:405:405:405:405:405:200:+++:::nginx/0.3.35
# nginx-devel-0.7.58 reverse proxy
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:404:411:405:405:405:405:403:404:::nginx/0.7.58 [reverse proxy]
# 403 on /
+++:HTM:HTM:403:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:400:405:405:405:405:405:403:+++::^nginx/0\.1\.2[4-8]:nginx/0.1.24-28 [broken configuration]
HTM:HTM:HTM:403:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:404:405:405:405:405:405:403:HTM:::nginx/1.4.1 [broken configuration]
# nginx/1.4.1	nginx/1.4.4
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:404:405:405:405:405:405:200:HTM:nginx/1:^nginx/1\.4\.[1-4]$:nginx/1.4.1-4
+++:200:400:200:200:200:400:400:400:400:+++:200:400:400:400:400:400:400:+++:+++:::NUD/3.6
+++:400:501:400:400:400:400:400:400:400:+++:200:501:501:501:501:501:501:+++:+++:::NUD/4.0.3
+++:200:---:200:200:---:---:---:---:200:+++:200:200:---:---:---:---:---:+++:+++:::NetPresenz/4.1
########
# Netscape-Enterprise/3.0
# Netscape-Enterprise/3.5.1G
# Netscape-FastTrack/3.01B
+++:HTM:200:200:200:500:200:400:200:404:404:200:500:401:401:200:500:400:404:+++:Netscape/3:^Netscape-(Enterprise|FastTrack)/3\.[025]:Netscape-Enterprise/3.0 to 3.5.1G or Netscape-FastTrack/3.01B
# Netscape-Enterprise/3.0L
# Netscape-Enterprise/3.5.1G
# Netscape-Enterprise/3.6 SP2
+++:HTM:200:400:200:500:400:400:400:404:404:400:500:401:401:200:500:400:404:+++:Netscape/3:^Netscape-Enterprise/3.[06]:Netscape-Enterprise/3.0L to 3.6 SP2
# Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:404:404:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:200:501:501:200:+++:Netscape/4 or Sun-ONE/6:^Netscape-Enterprise/[46]\.[01]:Netscape-Enterprise/4.1 to 6.0
# Netscape Enterprise 4.1 SP14 Administration web server (8888) on Windows 2000 Advanced Server with SP4
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:200:200:200:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1 [SP7 - SP14]
# Netscape-Enterprise/6.0
# Sun-ONE-Web-Server/6.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:200:501:501:200:+++:Netscape/4 or Sun-ONE/6:^(Netscape-Enterprise/(4\.1|6\.0)|Sun-ONE-Web-Server/6\.1):Netscape-Enterprise/4.1 to 6.1 (Sun-ONE-Web-Server)
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:405:405:200:501:501:200:+++:Sun-ONE/6::Netscape-Enterprise/6.1 AOL
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:405:501:501:200:+++:Sun-ONE/6::Sun-ONE-Web-Server/6.1
+++:---:500:505:HTM:501:302:HTM:HTM:HTM:HTM:400:500:500:500:500:501:501:302:+++:Sun-ONE/6 admin:^$:Sun-ONE-Web-Server/6.1 administration interface
# Sun One Web Server 6.1 on Sun Solaris 8
+++:HTM:200:505:HTM:501:500:HTM:HTM:HTM:HTM:400:+++:401:401:200:501:501:+++:+++:Sun-ONE/6::Sun-ONE-Web-Server/6.1
# Netscape-Communications/1.1
# Netscape-Communications/2.01
# Netscape-Communications/2.01c
# Netscape-Enterprise/2.0a
# Netscape-Enterprise/2.0d
# Netscape-FastTrack/2.01
# Netscape-FastTrack/2.01a
# Netscape-FastTrack/2.0a
# Netscape-Commerce/1.12
+++:HTM:404:200:200:500:400:400:400:404:404:200:500:500:500:500:500:500:404:+++:Netscape/1 or Netscape/2:^Netscape-(Commerce|Communications|Enterprise|FastTrack)/(1\.1|2\.0):Netscape/1.1 to 2.01c
+++:---:400:200:200:405:400:400:400:400:400:200:---:---:500:405:405:405:404:+++:Netscape/3::Netscape-Enterprise/3.6
# Is this reliable?
+++:HTM:200:400:400:400:400:400:400:404:404:400:404:404:404:200:404:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:200:200:400:HTM:500:200:HTM:HTM:HTM:HTM:400:404:401:401:200:500:404:404:+++:Netscape/4::Netscape-Enterprise/4.0
+++:200:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:200:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:200:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:405:405:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:200:400:400:200:400:200:404:404:200:404:401:401:200:404:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP2
+++:HTM:200:200:400:400:200:400:200:404:404:200:500:401:401:200:500:400:404:+++:Netscape/3:^Netscape-Enterprise/3.6( SP1)?$:Netscape-Enterprise/3.6 or 3.6 SP1
+++:HTM:200:200:400:400:200:400:200:404:404:200:500:500:500:200:500:500:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:400:400:400:400:400:400:404:404:400:404:401:401:200:400:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:400:200:500:400:400:400:200:404:400:500:401:401:200:500:400:404:+++:Netscape-FastTrack/3::Netscape-FastTrack/3.01
+++:HTM:200:400:400:400:400:400:400:200:404:400:500:401:401:200:500:400:404:+++:Netscape/3:^Netscape-Enterprise/3.6( SP1)?$:Netscape-Enterprise/3.6 or 3.6 SP1
+++:HTM:200:400:400:400:400:400:400:200:404:400:500:401:401:200:500:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP2
+++:HTM:200:400:400:400:400:400:400:---:---:400:500:401:401:200:500:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP2
+++:HTM:200:400:400:400:400:400:400:404:404:400:500:401:401:200:400:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:400:400:400:400:400:400:404:404:400:500:401:401:200:500:400:404:+++:Netscape/3::Netscape-Enterprise/3.6
+++:HTM:200:400:400:400:400:400:400:404:404:400:500:500:500:200:500:400:404:+++:Netscape/3::Netscape-Enterprise/3.6
+++:HTM:200:400:400:400:400:400:400:404:404:400:500:500:500:200:500:500:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP2
+++:HTM:200:400:HTM:500:200:HTM:HTM:HTM:HTM:400:404:401:401:200:500:404:404:+++:Netscape/4::Netscape-Enterprise/4.0
+++:HTM:200:400:HTM:500:200:HTM:HTM:HTM:HTM:400:404:500:500:200:500:500:404:+++:Netscape/4::Netscape-Enterprise/4.0
+++:HTM:200:505:HTM:501:200:HTM:---:HTM:HTM:400:404:401:401:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:---:HTM:HTM:400:404:405:405:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/6.0
+++:HTM:200:505:HTM:501:200:HTM:---:HTM:HTM:400:405:401:401:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:---:HTM:HTM:400:405:405:405:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:413:501:501:200:+++:Netscape/4:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 or 6.0
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:404:404:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:413:501:501:200:+++:Netscape/4:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 SP12 or 6.0
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:403:403:200:501:501:200:+++:Sun-ONE/6::Netscape-Enterprise/6.0
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:404:404:200:400:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:405:405:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:404:200:200:200:200:400:200:200:404:200:500:500:500:500:500:500:404:+++:Netscape-Enterprise/2::Netscape-Enterprise/2.01c
+++:HTM:404:400:200:500:400:400:400:404:404:200:500:500:500:500:500:500:404:+++:Netscape/3::Netscape-Enterprise/3.5.1G
+++:HTM:---:505:HTM:---:---:---:---:---:---:400:405:401:---:---:---:---:200:+++:Netscape/4::Netscape-Enterprise/4.1
+++:HTM:---:505:HTM:---:---:---:---:HTM:HTM:400:404:401:---:---:---:---:200:+++:Sun-ONE/6::Netscape-Enterprise/6.0
+++:XML:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:200:501:501:200:+++:Netscape/4 or Sun-ONE/6:^Netscape-Enterprise/(4\.1|6\.0):Netscape-Enterprise/4.1 or 6.0
#
+++:HTM:404:200:200:200:200:400:200:200:+++:+++:500:500:500:500:500:500:+++:+++:Netscape/3 (Netware)::Netscape-Enterprise/3.5-For-NetWare
+++:HTM:404:200:200:200:200:400:200:200:404:200:500:401:401:500:500:404:404:+++:Netscape/3 (Netware)::Netscape-Enterprise/3.5-For-NetWare
+++:HTM:200:200:400:400:200:400:200:404:+++:200:---:401:401:200:---:404:+++:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:400:400:400:400:400:400:404:+++:400:500:401:401:200:500:404:+++:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:400:400:400:400:400:400:404:404:400:404:401:401:200:404:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
+++:HTM:200:200:400:400:200:400:200:404:404:200:500:401:401:200:500:404:404:+++:Netscape/3:^Netscape-Enterprise/3\.6 SP[23]$:Netscape-Enterprise/3.6 SP2 or SP3
+++:HTM:200:200:400:400:200:400:200:200:404:200:500:404:404:200:500:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP2
+++:HTM:200:200:400:400:200:400:---:404:404:200:500:404:404:200:500:404:404:+++:Netscape/3::Netscape-Enterprise/3.6 SP3
# Solaris 8
+++:HTM:200:500:xxx:500:200:xxx:xxx:xxx:xxx:400:404:401:401:200:500:404:+++:+++:Netscape/4::Netscape-Enterprise/4.0 [Sun Solaris 8]
+++:HTM:200:200:HTM:200:200:HTM:HTM:HTM:+++:+++:200:200:200:200:200:200:+++:+++:Sun-ONE/6::Netscape-Enterprise/6\.0:SunONE 6.0 on Solaris 7
# Which SP?
+++:200:200:505:HTM:501:200:---:---:HTM:---:400:405:401:401:200:501:501:200:+++:Netscape/4::Netscape-Enterprise/4.1 (which SP?)
+++:HTM:200:505:HTM:501:401:HTM:HTM:HTM:+++:+++:401:401:401:200:501:501:401:+++:Netscape/4:Netscape-Enterprise/4\.1:Netscape Enterprise 4.1 SP13 console (access denied) on Linux
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:+++:+++:405:401:401:200:501:501:200:+++:Netscape/4 or Sun-ONE/6:Netscape-Enterprise/(4\.1|6\.0):iPlanet 4.1 SP13 or SunONE 6.0 SP1/SP6 on Linux
+++:HTM:200:505:HTM:501:401:HTM:HTM:HTM:+++:+++:500:500:500:200:501:501:401:+++:Sun-ONE/6:Netscape-Enterprise/6\.0:SunONE 6.0 SP1 or SP6 console (access denied) on Linux
+++:HTM:200:505:HTM:501:302:HTM:HTM:HTM:+++:+++:500:500:500:200:501:501:401:+++:Sun-ONE/6:Netscape-Enterprise/6\.0:SunONE 6.0 SP1 or SP6 console (access granted) on Linux
+++:HTM:200:505:HTM:501:500:HTM:HTM:HTM:HTM:400:405:401:401:200:501:501:+++:+++:Netscape/4:^Netscape-Enterprise/4\.1:iPlanet/4.5 SP10 on AIX
# Conflict with previous (less precise) signature
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:200:501:501:+++:+++:Sun-ONE/6::Netscape-Enterprise/6.0
# Broken banner?
+++:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:501:501:501:+++:+++:Sun-ONE/6:.USBR.:SunONE 6.1 on Solaris 8
+++:HTM:200:200:---:HTM:---:---:---:200:200:---:405:401:401:200:501:501:200:+++:Sun-ONE/6::Netscape-Enterprise/6.0 thru NetCache NetApp/5.5R4D6
#
+++:302:200:200:200:501:501:501:501:302:302:200:404:404:404:501:501:501:302:+++:::NetServe/1.0.41
#
+++:HTM:404:200:400:403:200:400:200:200:404:200:500:403:403:200:403:403:+++:+++:::NetWare-Enterprise-Web-Server/5.1
+++:HTM:404:200:400:403:400:400:400:200:404:400:500:403:403:200:403:403:+++:+++:::NetWare-Enterprise-Web-Server/5.1
+++:HTM:404:200:400:400:200:400:200:200:404:200:500:401:401:200:401:401:+++:+++:::NetWare-Enterprise-Web-Server/5.1
##200:200:200:200:200:200:---:200:200:---:---:---:200:200:200:200:200:200:200:200:200:200:200:200:+++:NetWare-Web-Manager/5.1
#
+++:200:400:200:400:302:200:400:405:400:400:200:411:405:---:400:---:400:+++:+++:::^NetWare HTTP Stack:Netware Management Portal, Netware 5.1 support pack 6
# Server Version 5.6.0 September 13, 2001 -  NDS Version 10110.20 September 6, 2001
+++:200:---:200:400:200:200:400:200:400:405:200:411:405:---:400:---:400:+++:+++:::^NetWare HTTP Stack:Netware Management Portal, Netware 6.0 w/o support pack
# Sun-Java-System-Web-Proxy-Server/4.0.7, Management Console on port 8081, raw signature
---:HTM:401:505:HTM:501:401:HTM:HTM:HTM:HTM:400:401:401:401:401:401:501:401:401:::Sun-Java-System-Web-Proxy-Server/4.0 [Management Console]
# Sun-Java-System-Web-Proxy-Server/4.0.7, proxy on port 8080
---:HTM:200:505:HTM:501:403:HTM:HTM:HTM:HTM:400:403:403:403:405:403:501:403:403:::Sun-Java-System-Web-Proxy-Server/4.0 [Web Proxy Server]
# www-servers/ocsigen-0.6.0 on Gentoo Linux
---:---:501:200:---:---:200:---:---:404:400:200:404:501:501:501:---:---:400:404:::Ocsigen server (0.6.0)
# www-servers/ocsigen-1.1.0 on Gentoo Linux
400:400:501:505:400:400:200:400:400:404:200:400:404:501:501:501:400:400:200:404:::Ocsigen [1.1.0]
+++:HTM:400:---:200:501:---:---:---:---:+++:400:404:403:403:403:501:501:+++:+++:::OmniHTTPd/2.10
---:---:404:302:---:---:---:---:---:---:---:---:404:404:404:404:---:---:---:---:operaunite:^Opera/[a-z0-9._-]+\.operaunite\.com$:Opera/operaunite.com
+++:500:501:200:200:200:500:500:500:302:302:200:404:405:405:405:405:405:302:+++::^$:OMSA (Dell OpenManage Server Administrator)
+++:500:501:200:---:200:500:500:500:302:302:200:404:405:405:405:405:405:302:+++::^$:Dell OpenManage 3.6
200:500:501:200:200:200:500:500:500:302:200:200:404:200:200:200:200:200:302:404::^$:Dell OpenManage 6.2.0
+++:505:501:505:505:200:505:505:505:200:200:200:200:501:501:501:501:501:+++:+++::^XES 8830 WindWeb/1\.0:OkiDATA C7300dxn printer on OKI-6200e+ Print Server
# Oracle9iAS (9.0.3.0.0) Containers for J2EE
# Oracle9iAS (9.0.4.0.0) Containers for J2EE
# Oracle Application Server Containers for J2EE 10g (9.0.4.0.0)
+++:---:400:200:---:400:---:---:---:400:+++:200:100:404:404:404:404:404:+++:+++:Oracle9iAS:^(Oracle9iAS|Oracle Application Server).*Containers for J2EE:Oracle AS containers for J2EE (9i or 10g)
# Windows XP Pro (version 2002) 32bit SP3 - Oracle Application Server Release 3 (10.1.3)
---:---:400:200:---:400:---:---:---:400:---:200:404:404:404:404:404:404:200:404:::Oracle Containers for J2EE [Oracle Application Server Release 3 (10.1.3)]
# More precise
---:---:400:200:---:400:---:---:---:400:400:200:100:404:404:404:404:404:200:404:Oracle9iAS::Oracle Application Server Containers for J2EE 10g (9.0.4.1.0)
# Oracle9iAS (9.0.2.0.0) Containers for J2EE
# Oracle9iAS (1.0.2.2.1) Containers for J2EE
+++:---:400:200:---:200:---:400:200:400:+++:200:100:404:404:404:404:404:+++:+++:Oracle9iAS:^Oracle9iAS \([19]\.0\.2\.[02]\.[01]\) Containers for J2EE:Oracle9iAS Containers for J2EE
# MS-Author-Via: DAV
# Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - 64bit Production
# Oracle XML DB/Oracle9i Release 9.2.0.1.0 - Production
+++:---:200:505:400:501:---:---:---:200:200:400:200:200:200:200:200:501:+++:+++:Oracle XML DB/Oracle9i::Oracle XML DB/Oracle9i Release 9.2.0.1.0
# More precise. The same?!
+++:---:200:505:400:501:---:---:---:200:200:400:200:200:200:200:200:501:200:+++:Oracle XML DB/Oracle9i::Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production
# Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - 64bit Production
# Oracle XML DB/Oracle9i Enterprise Edition Release 9.2.0.1.0 - Production
# Oracle XML DB/Oracle9i Release 9.2.0.1.0 - Production
400:---:200:505:400:501:---:---:---:200:200:400:200:200:200:200:200:501:200:200:Oracle XML DB/Oracle9i:^Oracle XML DB/Oracle9i ([A-Z][a-z]+ )*9\.2\.0\.1\.0 - (64bit )?Production:Oracle XML DB/Oracle9i Release 9.2.0.1.0
# Unreliable signature: a proxy was on the way
+++:xxx:200:200:200:200:200:HTM:xxx:400:+++:400:404:404:404:404:404:404:+++:+++:Oracle9iAS::Oracle9iAS (1.0.2.2.1) Containers for J2EE
+++:400:200:200:400:200:400:400:400:200:200:400:+++:100:200:200:200:200:+++:+++:Oracle9iAS-Web-Cache::Oracle9iAS-Web-Cache/9.0.2.0.0
+++:400:501:200:400:200:400:400:400:400:400:400:+++:100:501:501:501:501:+++:+++:Oracle9iAS-Web-Cache::Oracle9iAS-Web-Cache/9.0.2.0.0
+++:400:403:200:400:501:400:400:400:200:400:400:+++:100:404:200:404:501:+++:+++:Oracle9iAS::Oracle9iAS/9.0.2 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.0.0 (N)
+++:200:200:200:400:501:200:400:400:400:+++:400:404:405:404:200:404:501:+++:+++:Oracle AS 10g::Oracle AS10g/9.0.4 Oracle HTTP Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
# Oracle-Application-Server-10g/10.1.2.0.2 Oracle-HTTP-Server OracleAS-Web-Cache-10g/10.1.2.0.2 (G;max-age=0+0;age=0;ecid=3524385735406,0)
# Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
+++:200:200:200:400:501:200:400:400:200:400:400:404:405:404:200:404:501:403:+++:Oracle AS 10g:^Oracle-Application-Server-10g/(9|10)\.[0-9.]+ Oracle-HTTP-Server OracleAS-Web-Cache-10g/(9|10)\.[0-9.]+:Oracle-Application-Server-10g Oracle-HTTP-Server OracleAS-Web-Cache-10g
+++:HTM:403:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:+++:Oracle AS 10g::Oracle-Application-Server-10g/10.1.2.0.2 Oracle-HTTP-Server
+++:200:501:200:400:200:200:400:400:400:+++:400:404:501:501:501:501:501:+++:+++:OracleAS-Web-Cache-10g::OracleAS-Web-Cache-10g/9.0.4.0.0
# More precise
+++:200:501:200:400:200:200:400:400:400:400:400:404:501:501:501:501:501:404:+++:Oracle-Web-Cache/10g::Oracle-Web-Cache/10g (10.1.2)
+++:400:200:200:400:501:400:400:400:400:+++:400:100:100:404:200:404:501:+++:+++:Oracle9iAS::Oracle9iAS/9.0.2 Oracle HTTP Server Oracle9iAS-Web-Cache/
### More precises
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server (Unix) DAV/1.0.2 (OraDAV enabled) mod_plsql/9.0.2.6.0 mod_osso/9.0.2.0.0 mod_oc4j/3.0 mod_ossl/9.0.2.0.0 mod_fastcgi/2.2.10 mod_perl/1.26 Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
# Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
+++:400:200:200:400:501:400:400:400:400:400:400:100:100:404:200:404:501:200:+++:Oracle9iAS:^Oracle9iAS/9\.0\.2[0-9.]* Oracle HTTP Server.* Oracle9iAS-Web-Cache/9\.0\.2[0-9.]*:Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N) [unix]
+++:400:200:200:400:501:400:400:400:400:400:400:100:100:404:200:404:501:403:+++:Oracle9iAS::Oracle9iAS/9.0.2.3.0 Oracle HTTP Server Oracle9iAS-Web-Cache/9.0.2.3.0 (N)
#
+++:200:200:200:400:501:200:400:400:200:400:400:+++:405:404:200:404:501:+++:+++:Oracle AS 10g::Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server OracleAS-Web-Cache-10g/9.0.4.0.0 (N)
# TCP port 1830 - X-ORCL-EMSV: 4.0.1.0.0
+++:400:400:400:400:200:400:400:400:200:400:200:+++:400:400:400:400:400:+++:+++:Oracle AS 10g::Oracle-Application-Server-10g/9.0.4.0.0 [Oracle Net8 Cman Admin]
+++:200:200:200:400:200:200:400:400:200:200:400:+++:200:200:200:200:200:+++:+++:OracleAS-Web-Cache-10g::OracleAS-Web-Cache-10g/9.0.4.0.0
+++:200:200:200:400:200:200:400:400:200:200:400:200:200:200:200:200:200:200:+++:OracleAS-Web-Cache-10g::OracleAS-Web-Cache-10g/10.1.2.0.2
###
+++:---:400:VER:---:---:200:---:---:400:400:200:404:400:400:400:400:400:414:+++:::orenosv/1.0.0
# Orion (java server)
+++:200:400:200:---:200:404:400:200:400:+++:+++:100:404:404:404:404:404:+++:+++:::Orion/2.0.1
+++:---:400:200:---:501:---:400:200:400:400:200:100:404:404:404:404:404:400:+++:::Orion/1.5.2
# VMS web server
+++:HTM:403:200:200:xxx:200:xxx:xxx:403:403:200:501:401:501:501:501:501:401:+++:::OSU/3.10a;UCX
+++:HTM:403:200:200:xxx:200:xxx:xxx:403:+++:200:403:403:403:403:403:403:+++:+++:::OSU/3.2alpha2
+++:HTM:403:200:200:xxx:200:xxx:HTM:403:403:200:403:403:403:403:403:403:501:+++:::OSU/3.9c;UCX
# More precise
+++:HTM:403:200:200:xxx:200:xxx:xxx:403:403:200:403:403:403:403:403:403:200:+++:::OSU/3.6b;Multinet
+++:HTM:403:200:200:xxx:200:xxx:xxx:403:403:200:501:501:501:501:501:501:200:+++:::OSU/3.3b
+++:HTM:404:200:200:200:HTM:HTM:HTM:404:404:200:404:404:404:404:404:404:---:+++:::Purveyor Encrypt Export/v2.1 OpenVMS
# Palo Alto PAN-OS PanWeb
---:---:---:---:---:---:---:---:---:404:---:200:404:---:---:---:---:---:200:404:PanWeb Server:^PanWeb Server/:PanWeb on Palo Alto PAN-OS
# PlanetDNS
+++:404:---:200:200:---:---:---:---:200:400:200:404:---:---:---:---:---:404:+++:mshweb/1.1:^mshweb/1\.1[0-9] NewAce Corporation:mshweb/1.1x [PlanetDNS web plugin]
#
+++:400:400:200:200:200:400:400:400:400:+++:200:---:---:---:---:---:---:+++:+++:::Polycom-WS/1.0
HTM:HTM:404:VER:VER:VER:200:HTM:HTM:404:404:200:501:501:501:501:501:501:HTM:HTM:::Polycom SoundPoint IP Telephone HTTPd
# Plain Old Webserver - a firefox extension
200:404:400:200:200:400:400:404:400:400:400:200:404:400:400:400:400:400:200:404:::POW/0.1.8
#
# Same server. Scalar... is the old banner, Enterprise... the new one which supports Scalar i6000
# Scalar i2k Simple Webserver
# Enterprise Tape Library Simple Webserver
200:200:501:200:200:200:200:501:501:200:200:200:501:501:501:501:501:501:200:404::^(Scalar i2k Simple Webserver|Enterprise Tape Library Simple Webserver):Enterprise Tape Library Simple Webserver [Quantum Scalar i2000-i6000]
# Used with some RAID hardware (IBM??)
+++:400:501:505:505:505:505:400:400:505:505:404:501:501:501:501:501:501:505:+++::^$:ServeRAID Manager File Server
+++:---:---:200:200:200:---:---:---:---:---:200:+++:405:---:---:---:---:+++:+++:::Sipura SPA-3000 3.1.7(GWc)
# SiteCom LN-300 - single port parallel print server
+++:HTM:---:200:200:---:200:---:---:---:200:200:---:---:---:---:---:---:+++:+++::^PRINT_SERVER WEB 1\.0:SiteCom LN-300 print server
200:200:200:200:200:200:200:999:999:200:200:200:200:200:200:200:200:200:200:200:::SiteScope/7.6 C2
# Quicktime?
+++:400:400:400:400:400:200:400:400:302:+++:200:404:400:400:400:400:400:+++:+++:::QTSS 3.0 Admin Server/1.0
# Publicfile 0.52 by DJB
+++:HTM:501:404:400:501:HTM:HTM:HTM:404:404:400:501:501:501:501:501:501:404:+++:::publicfile [not yet configured]
+++:HTM:501:200:400:501:HTM:HTM:HTM:404:404:400:501:501:501:501:501:501:200:+++:::publicfile
# Generic web server by WindRiver
+++:HTM:200:505:400:200:500:400:400:400:+++:400:404:404:404:200:404:404:+++:+++:::Rapid Logic/1.1
+++:---:501:200:200:200:---:---:---:404:+++:200:500:501:501:501:501:501:+++:+++:::RapidLogic/1.1
200:---:501:200:200:200:---:---:---:404:---:200:500:501:501:501:501:501:404:---:::UOS [TippingPoint X505]
+++:404:---:200:200:200:---:---:---:404:+++:200:---:---:---:---:---:---:+++:+++:::RapidLogic/1.1
# web server installed on a Nortel Passport-8606
+++:---:501:200:200:200:---:---:---:---:---:200:500:501:501:501:501:501:---:+++:::Rapid Logic/1.1
# Raiden with PHP/4.3.10 or PHP/5.0.3
+++:400:501:200:400:400:400:400:400:400:400:400:404:501:501:501:501:501:400:+++:::RaidenHTTPD/1.1.35 (Shareware)
# Resin/2.1.11 (Windows)
# Resin/2.1.10
# Resin/2.1.9 (Gentoo/Linux) - standard & EE
# Resin/2.0.4
+++:HTM:HTM:200:HTM:200:200:---:---:HTM:HTM:400:404:501:501:501:501:501:200:+++:::Resin/2
+++:HTM:HTM:200:HTM:200:200:---:---:HTM:---:400:200:405:405:405:501:501:200:+++:Resin/2::Resin/2.1.4
+++:HTM:HTM:200:HTM:500:500:---:---:HTM:HTM:400:404:501:501:501:501:501:500:+++:Resin/2::Resin/2.1.12
+++:xxx:HTM:200:xxx:302:302:---:---:xxx:xxx:400:200:501:501:501:501:501:302:+++:Resin/2::Resin/2.1.6
+++:HTM:HTM:HTM:HTM:200:200:HTM:HTM:HTM:HTM:400:---:200:200:200:200:200:200:+++:Resin/3.0::Resin/3.0.5
+++:HTM:HTM:HTM:200:200:200:HTM:HTM:HTM:---:400:404:501:501:501:501:501:200:+++:Resin/3.0::Resin/3.0.6
+++:HTM:HTM:HTM:400:200:200:HTM:HTM:HTM:---:400:404:501:501:501:501:501:200:+++:Resin/3.0::Resin/3.0.6
# Very odd - I got two different signatures on a Win32 machine (the Resin/2 above and this one)
+++:400:500:200:400:400:200:400:400:500:500:200:404:501:501:200:501:501:200:+++:Resin/2::Resin/2.1.11
# www-servers/resin-3.0.22 (on Gentoo)
# www-servers/resin-3.0.23-r1
# Resin/3.0.s070602
# Resin/3.0.s070917 = www-servers/resin-3.0.24
# Resin/3.0.s080512 = www-servers/resin-3.0.25
HTM:HTM:HTM:HTM:HTM:200:200:HTM:HTM:HTM:---:400:---:501:501:501:501:501:200:400:Resin/3.0:Resin/3\.0\.s0[78]0[59][01][27]:Resin/3.0.s070602-Resin/3.0.s080512
# www-servers/resin-3.1.1-r1
#+++:HTM:HTM:HTM:HTM:200:200:HTM:HTM:HTM:---:400:404:501:501:501:501:501:200:+++:Resin/3.1::Resin/3.1.s070602
# www-servers/resin-3.1.2
# Resin/3.2.s090702 = www-servers/resin
# Resin/3.1.7
HTM:HTM:HTM:HTM:HTM:200:200:HTM:HTM:HTM:---:400:404:501:501:501:501:501:200:400:Resin/3.1 or Resin/3.2:Resin/3\.[12]\.(7|s0[79]0[679][01][27]):Resin/3.1.s070602-Resin/3.2.s090702
+++:HTM:200:200:400:400:200:400:400:400:400:400:404:405:405:200:400:400:200:+++:::Rock/1.4.2
+++:HTM:404:VER:400:400:HTM:HTM:HTM:404:302:400:200:405:405:404:404:404:200:+++:::Roxen/2.2.252
# Administration interface on port 22202
+++:HTM:404:200:400:400:HTM:HTM:HTM:200:302:400:200:200:200:200:200:200:200:+++:::Roxen/4.0.325-NT-release4 [administration interface]
#
+++:HTM:404:VER:400:400:HTM:HTM:HTM:404:404:400:404:404:404:404:404:404:404:+++:::Roxen/4.0.325-NT-release4 [not configured]
+++:HTM:404:200:400:400:HTM:HTM:HTM:200:302:400:404:405:404:501:501:501:200:+++:::Roxen/4.0.325-NT-release4
#
+++:200:501:200:200:404:---:---:200:200:404:200:400:400:501:501:501:501:404:+++:::SAMBAR
+++:200:404:200:200:404:---:---:200:200:404:200:400:400:401:401:401:401:404:+++:sambar::SAMBAR 5.0
200:200:204:200:200:404:---:---:200:200:404:200:204:204:204:204:204:204:404:+++:sambar:^SAMBAR$:SAMBAR 6.4 - 7.0 (Linux)
200:200:204:200:200:404:---:---:200:200:404:200:204:204:204:204:204:204:404:200:sambar:^SAMBAR$:SAMBAR 7.0 (Linux)
200:200:204:200:200:404:---:---:200:200:404:200:204:204:204:204:204:204:404:400:sambar:^SAMBAR$:SAMBAR 6.4 (Linux)
# Also used by MySQL as MaxDB
+++:200:404:200:400:400:400:400:400:404:400:400:400:400:404:404:404:400:404:+++:::SAP-Internet-SapDb-Server/1.0 [MaxDB]
# Savant
+++:xxx:500:400:400:200:200:xxx:xxx:200:500:200:405:405:405:405:405:405:---:+++:::Savant/3.1
# sh-httpd 0.3 or 0.4 (who uses this gizmo?)
+++:200:501:200:200:501:200:501:200:404:+++:200:501:501:501:501:501:501:404:+++::ShellHTTPD/:sh-httpd
+++:HTM:200:VER:HTM:200:200:---:---:200:200:400:200:200:200:200:200:200:+++:+++:::SilverStream Server/10.0
# SkunkWeb 3.4.1
# SkunkWeb 3.4b5
+++:HTM:xxx:VER:VER:xxx:xxx:xxx:xxx:404:500:200:200:xxx:xxx:xxx:xxx:xxx:200:+++::^SkunkWeb 3\.4(b5|\.1):SkunkWeb 3.4b5 or 3.41
+++:HTM:xxx:VER:VER:xxx:xxx:xxx:xxx:404:500:200:200:xxx:xxx:xxx:xxx:xxx:---:+++:::SkunkWeb 3.4b5
+++:501:xxx:404:404:xxx:xxx:xxx:xxx:501:xxx:404:xxx:xxx:xxx:xxx:xxx:xxx:404:+++::^$:Skype [not a real web server]
+++:200:400:200:200:200:400:400:400:200:404:200:---:400:400:400:400:400:+++:+++:::AnalogX SimpleServer 1.23
# Slimdevices's SlimServer 5.1
+++:400:400:400:400:200:400:400:400:400:400:200:400:400:400:400:400:400:+++:+++::^$:SlimServer 5.1
400:400:501:401:400:501:501:501:501:400:501:400:401:501:501:501:501:501:400:400::^$:Sofaware FW & VPN box
# SonicWALL, model# SOHO 3 (CPU: Toshiba 3927 H2 / 133 Mhz), running firmware v6.5.0.4.
+++:---:---:200:---:---:---:---:---:200:---:200:+++:---:---:---:---:---:+++:+++:::SonicWALL [v6.5.0.4]
# ---:200:400:200:200:200:400:400:200:400:400:400:400:200:200:+++:200:404:404:400:400:400:400:400:+++:SonicWALL
# More precise
+++:---:400:200:200:400:400:400:400:200:404:200:404:404:400:400:400:400:+++:+++:::SonicWALL
+++:---:400:200:200:400:400:400:400:200:+++:200:404:404:400:400:400:400:+++:+++:::SonicWALL
# PRO 330 / Firmware 6.5.0.4 / ROM  6.4.0.0 / VPN Hardware Accelerator
+++:---:---:200:---:---:---:---:---:200:---:200:---:---:---:---:---:---:+++:+++:::SonicWALL
# SonicOS 5.8 on SonicWALL NSA 220
---:---:---:200:---:---:---:---:---:200:404:200:404:404:404:---:---:---:400:400:SonicWALL:^SonicWALL:SonicWALL
+++:200:200:200:200:200:200:200:200:404:404:200:404:200:200:200:200:200:200:+++:::SCO I2O Dialogue Daemon 1.0
404:404:404:200:200:200:400:404:200:404:404:200:404:500:500:501:501:501:200:404:shttpd:^$:shttpd 1.25
404:404:404:200:200:200:400:404:200:404:404:200:404:401:401:501:501:501:200:404:shttpd:^$:shttpd 1.35
# shttpd is now called mongoose
400:400:400:505:400:400:400:400:400:400:400:200:404:401:401:400:400:400:200:404:mongoose:^$:mongoose 2.8
400:400:200:505:505:400:400:400:400:400:400:200:404:401:401:400:400:400:200:404:moongose:^$:mongoose 5.3
# dev-python/spawning-0.8.10
500:500:500:HTM:HTM:HTM:500:HTM:HTM:500:500:500:500:500:500:500:500:500:500:500:spawn:^$:spawning [not configured]
# Splunk Forwarder version 4.2.1-98164. listening on port 8089.
200:200:501:200:200:400:400:400:400:404:501:200:404:404:404:501:400:400:200:404:::Splunkd [Splunk Forwarder version 4.2.1-98164]
# Spyglass_MicroServer/2.01FC1
# Spyglass_MicroServer/2.00FC4
+++:HTM:404:200:HTM:200:HTM:HTM:HTM:404:+++:400:100:100:404:404:404:404:+++:+++:::Spyglass_MicroServer/2.0
#
+++:400:400:200:400:400:403:400:400:400:400:403:411:411:403:200:400:411:403:+++:::Microsoft-IIS/5.0 thru Squid/2.5STABLE3 reverse proxy
#
+++:---:500:---:---:---:---:---:---:500:500:500:411:404:404:404:404:404:500:+++:Tcl-Webserver/3::Tcl-Webserver/3.3 March 12, 2001
+++:---:500:---:---:---:---:---:---:500:500:200:411:404:404:404:404:404:200:+++:Tcl-Webserver/3::Tcl-Webserver/3.4.2 September 3, 2002
+++:---:200:---:---:---:---:---:---:200:200:200:411:200:200:200:200:200:200:+++:Tcl-Webserver/3::Tcl-Webserver/3.5.1 May 27, 2004
# Tiny HTTPD
# thttpd/2.14 31jan00
# thttpd/2.15 08feb00
# thttpd/2.16 29feb00
# thttpd/2.17 10may00
# thttpd/2.18 13jun00
# thttpd/2.19 23jun00
+++:HTM:501:VER:VER:VER:200:400:400:400:400:400:404:501:501:501:501:501:400:+++:thttpd/2.1x:thttpd/2\.1[4-9]:thttpd/2.14-2.19
# thttpd/2.12 00jan00
# thttpd/2.20 27sep00
# thttpd/2.20c 21nov01
# thttpd/2.20b 10oct00
+++:HTM:501:VER:VER:VER:200:400:400:400:400:400:404:501:501:501:501:501:200:+++:thttpd/2:^thttpd/2\.[12]:thttpd/2.12 or thttpd/2.20-2.21
# thttpd/2.21 20apr2001
# thttpd/2.21b 23apr2001
+++:HTM:HTM:VER:VER:VER:200:HTM:HTM:HTM:HTM:400:404:HTM:HTM:HTM:HTM:HTM:200:+++:::thttpd/2.21
HTM:HTM:501:VER:VER:VER:200:HTM:HTM:200:200:400:404:501:501:501:501:501:400:404:::thttpd/2.24 26oct2003
+++:HTM:501:VER:VER:VER:200:xxx:xxx:200:200:400:404:501:501:501:501:501:400:+++:::thttpd/2.24
+++:HTM:501:HTM:HTM:200:200:HTM:HTM:200:+++:+++:404:501:501:501:501:501:400:+++::^thttpd/2\.2:thttpd/2.24
+++:HTM:501:HTM:HTM:200:200:400:400:400:+++:+++:404:501:501:501:501:501:200:+++:::thttpd/2.20c
+++:HTM:400:VER:VER:VER:200:xxx:xxx:400:400:400:404:501:501:501:501:501:+++:+++:::thttpd/2.25b 29dec2003
# thttpd/2.25 19dec2003
# thttpd/2.25b 29dec2003
# www-servers/thttpd-2.26.2
HTM:HTM:400:VER:VER:VER:200:HTM:HTM:400:400:400:404:501:501:501:501:501:400:404:thttpd:thttpd(/2\.2[56](\.[0-9])?)?$:thttpd/2.25-2.26.2
+++:XML:400:VER:VER:VER:200:HTM:HTM:400:400:400:404:501:501:501:501:501:400:+++:::thttpd [thttpd-2.25b-12.fc6]
+++:501:501:501:501:VER:501:501:501:501:501:400:404:501:501:501:501:501:400:+++::^thttpd/2\.25b:thttpd/2.25b through pound reverse proxy
501:501:501:501:501:VER:501:501:501:400:400:400:403:501:501:501:501:501:400:404::^thttpd/2\.25b:thttpd/2.25b through pound reverse proxy v2.5
501:501:400:501:501:VER:501:501:501:400:400:400:403:501:501:501:501:501:400:404::^thttpd/2\.25b:thttpd/2.25b through pound reverse proxy v2.5 [xHTTP >= 2]
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:501:501:501:501:501:200:404::^thttpd/2\.25b:thttpd/2.25b through Apache/2.2 mod_proxy
# thttpd/2.25b on a Pitney Bowes Digital Mailing System
---:---:---:200:VER:---:200:HTM:---:400:400:400:404:501:501:---:501:501:400:404:::thttpd/2.25b
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:405:403:403:200:400:411:200:414:::Microsoft-IIS/5.0 through Apache/2.2 mod_proxy
HTM:HTM:200:200:200:404:200:HTM:HTM:400:400:400:411:411:404:404:404:404:200:400:::Microsoft-IIS/7.5 through Apache/2.2 mod_proxy
#
+++:HTM:404:200:HTM:400:HTM:HTM:HTM:400:400:400:411:404:404:404:404:HTM:400:+++:::tigershark/3.0
+++:302:404:302:302:405:400:400:400:404:400:302:405:405:405:405:405:405:414:+++:::Tipic Console/1.0.2345.27295
# voice-over-IP telephone
+++:---:403:505:505:505:200:---:---:200:403:200:404:403:403:403:400:400:+++:+++::^$:tiptel innovaphone 200
+++:400:403:200:400:400:400:400:400:403:403:200:302:403:403:403:403:403:403:+++::^TinyWeb/1\.9[12]:TinyWeb/1.91-92
# More precise & conflicting
400:400:403:200:400:400:400:400:400:403:403:200:302:403:403:403:403:403:403:403:::TinyWeb/1.93
# Tiny Java WebServer
+++:HTM:501:VER:VER:VER:200:HTM:HTM:200:200:400:501:501:501:501:501:501:200:+++:tjws:^$:TJWS/1.30
+++:200:---:200:200:200:---:---:---:HTM:+++:200:---:---:---:---:---:---:+++:+++:::Toaster
200:200:---:200:200:200:200:404:404:404:---:200:400:---:---:---:---:---:404:404:::tor-0.1.2
200:200:---:200:200:200:200:404:404:404:---:200:404:---:---:---:---:---:404:404:::Tor directory server (?)
---:---:405:VER:VER:---:---:---:---:404:404:200:404:404:404:405:405:405:404:404:::TornadoServer/0.1
400:400:401:401:401:401:400:400:400:401:401:401:501:501:501:501:501:501:501:413:::TP-LINK Router
+++:400:200:VER:VER:VER:200:400:200:200:200:200:200:200:200:200:200:200:200:+++:::TwistedWeb/2.0.1
# Tomcat  4.0.1 on a Sun Management Console (SMC 3.5)
##HTM:200:400:200:200:200:400:501:400:400:400:414:414:400:400:+++:+++:405:405:405:200:200:501:501:+++:Tomcat/2.1
+++:HTM:400:200:200:501:400:400:414:400:400:200:405:405:405:200:501:501:+++:+++:Apache-Tomcat/2.1:^Tomcat/2\.1:Apache Tomcat/2.1 [Sun Management console]
# More precise but unknown version
HTM:HTM:400:200:200:501:400:400:414:400:400:200:405:405:405:200:501:501:414:414:Apache-Tomcat/2.1:^Tomcat/2\.1:Apache Tomcat/2.1 [Sun Management console]
+++:HTM:200:200:200:200:200:400:400:200:+++:200:200:200:200:200:200:200:+++:+++:Apache-Tomcat/3.3::Apache Tomcat Web Server/3.3.1 Final
# tomcat5-5.5.23-0jpp.40.el5_9 on Scientific Linux release 5.10 (Boron)
XML:XML:200:505:505:505:---:---:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 5.5.23]
# www-servers/tomcat-6.0.18-r1 on Gentoo
# www-servers/tomcat-5.5.27-r1 on Gentoo
HTM:HTM:200:505:505:505:200:---:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 5.5 or 6.0]
# Tomcat 7.0.69 on Oracle Linux 7
# Tomcat 7.0.69 on RHEL 7
HTM:HTM:200:505:505:400:200:---:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 7.0.69]
# tomcat 8.0.3 on openSuSE 42.1 (tomcat-8.0.23-2.1.noarch)
HTM:HTM:200:505:505:505:200:400:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 6.0.20 or 6.0.29 or 8.0.23]
HTM:HTM:200:505:505:505:200:400:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 6.0.29]
HTM:HTM:200:505:505:505:200:400:---:400:400:400:404:403:403:405:501:501:200:---:::Apache-Coyote/1.1 [Tomcat 5.5.31]
+++:HTM:400:505:505:505:---:---:---:200:400:400:404:403:403:200:501:501:200:+++:Apache-Coyote/1.0:Apache Coyote/1\.0:Apache Tomcat [LiteWebServer]
+++:---:400:505:505:505:---:---:---:404:+++:+++:404:403:403:200:501:501:+++:+++:Apache-Coyote/1.0:Apache Coyote/1\.0:Apache Tomcat 4.2.24
+++:---:200:505:---:---:---:---:---:---:---:---:404:403:403:200:501:501:+++:+++:Apache-Coyote/1.1:Apache-Coyote/1\.1:Apache Tomcat 5.0.14 Beta
+++:HTM:200:505:505:505:---:---:---:200:+++:400:404:403:403:200:501:501:+++:+++:Apache-Coyote/1.1::Apache-Coyote/1.1
+++:XML:200:505:505:505:---:---:---:200:400:400:404:403:403:405:501:501:200:+++:Apache-Coyote/1.1::Apache-Coyote/1.1 [Servlet 2.4; JBoss-4.0.3RC2]
# More precise
XML:XML:200:505:505:505:---:---:---:200:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1::Apache-Coyote/1.1 [Apache Tomcat 5.5.20 on Windows 2003 Server]
# Tomcat 6.0.18
---:---:200:505:505:505:200:---:---:400:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 6.0.18
# Tomcat 6.0.18 on Windows
---:---:---:505:505:---:200:---:---:400:400:400:404:403:403:---:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 6.0.18
# Tomcat 7.0.28 on Debian 7
XML:XML:200:505:505:400:200:---:---:400:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 7.0.28
# Tomcat 7.0.54 (on FreeBSD 9.3)
---:---:---:505:505:---:200:400:---:400:400:400:404:403:403:---:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 7.0.54
# Tomcat 7.0.56 on Debian 8
XML:XML:200:505:505:---:200:400:400:400:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 7.0.56
XML:XML:200:505:505:400:200:400:---:---:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1:Apache-Coyote/1\.1:Tomcat 7.0.56
# Tomcat 7.0.64 on Ubuntu 15.10
XML:XML:200:505:505:505:200:---:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 7.0.64]
XML:XML:200:505:505:505:200:400:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [Tomcat 7.0.64]
# BlackBerry Mobile Data Service Connection Service
# Build number  : 15
# Build version : 4.1.2.15
# Build Date    : 2006/08/15
+++:HTM:200:505:505:505:---:---:---:200:400:400:404:403:403:405:501:501:200:+++:Apache-Coyote/1.1::Apache-Coyote/1.1 [BlackBerry Mobile Data Service Connection Service]
# More precise & conflicting
HTM:HTM:200:505:505:505:---:---:---:200:400:400:404:403:403:405:501:501:200:404:Apache-Coyote/1.1::Apache-Coyote/1.1
# product:  tamino; vendor: softwareag; os: w2k; is an xml-database. port 9991 is used by the webinterface.
+++:HTM:501:200:HTM:HTM:HTM:HTM:HTM:404:404:200:501:501:501:501:501:501:+++:+++:::ARGHTTPD/2.1.1.1 [Tamino XML database web interface]
# Tux kernel HTTP server on CentOS 4.5 or CentOS 5
+++:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:200:+++:::TUX/2.0 (Linux)
##404:404:404:404:404:404:404:404:404:+++:404:404:404:404:404:404:404:+++:
# Universal Share Downloader (USD) 1.3.4.8 web-interface (Program for automatic download from share-services (as rapidshare, megaupload etc))
200:200:501:VER:VER:200:501:501:200:200:403:200:+++:501:501:501:501:501:+++:+++:USD:^$:Universal Share Downloader (USD) 1.3.4.8 web-interface
+++:404:404:200:200:404:404:404:404:404:404:200:+++:404:404:404:404:404:+++:+++:::UPS_Server/1.0
# More precise & conflicting
200:404:404:200:200:404:404:404:404:404:404:200:404:404:404:404:404:404:404:404:::3ware/2.0
# UserLand Frontier/9.0-WinNT
# UserLand Frontier/9.0.1-WinNT
+++:400:404:505:400:200:400:400:400:400:400:400:200:404:404:404:404:404:200:+++::^UserLand Frontier/9\.0(.1)?-WinNT:UserLand Frontier/9.0-WinNT
+++:400:302:505:400:200:400:400:400:400:400:400:200:200:200:200:200:200:200:+++:::UserLand Frontier/9.0.1-WinNT [not configured]
# userver-0.3.0 -> userver-0.4.4
+++:---:---:400:400:---:200:---:200:404:200:200:---:---:---:---:---:---:400:+++:userver:^userver-0\.[34]:userver-0.3 or 0.4
+++:404:501:400:400:400:404:400:404:404:403:404:400:501:501:501:501:501:400:+++:userver::userver-0.5.1 [no index.html]
+++:200:501:400:400:400:200:400:200:404:403:200:400:501:501:501:501:501:400:+++:userver::userver-0.5.1
200:500:---:200:200:200:---:---:---:200:404:200:---:---:---:---:---:---:404:404:::webcamXP
# weborf 0.12.4 (previous versions crash)
VER:404:VER:VER:VER:400:400:400:400:404:400:VER:404:403:403:400:400:400:VER:400:::Weborf (GNU/Linux)
400:HTM:200:200:400:400:200:400:400:400:400:200:404:404:404:404:404:404:200:404:::WEBrick/1.3.1 (Ruby/1.8.2/2004-12-25)
# VMS
+++:HTM:400:200:200:200:HTM:HTM:HTM:404:+++:+++:404:400:400:400:400:400:200:+++:::Webshare/1.2.3 VM_ESA/2.3.0.9808 CMS/14.808 REXX/4.01 CMS_Pipelines/1.0110 REXX_SOCKETS/3.01
#
+++:400:400:200:200:400:400:400:400:200:200:200:200:400:400:400:400:400:+++:+++:::Vertical Horizon VH-2402S
+++:404:501:200:200:200:404:501:400:400:+++:200:404:501:501:501:501:501:+++:+++:::Viavideo-Web
+++:---:200:200:---:200:---:---:---:403:403:200:403:403:405:200:501:501:403:+++:::VisiBroker/4.0
200:200:403:200:200:200:---:---:---:---:200:200:404:403:403:403:403:403:---:---:VisualRoute::VisualRoute (R) 2008 Server NOC Edition (v12.0d)
200:200:400:200:200:400:404:404:404:404:404:200:400:400:400:400:400:400:200:404::^$:vmware infrastructure
400:400:501:200:200:501:400:400:400:404:404:200:400:400:400:501:501:501:200:404::^$:vmware ESXi
400:400:501:200:200:501:400:400:400:404:404:200:200:200:200:501:501:501:200:200:::VMware vCenter Server Appliance
400:400:501:301:301:501:400:400:400:404:404:301:301:301:301:501:501:501:301:301:::VMware vCenter Server Appliance
# VNC HTTPD (no banner!)
+++:200:---:200:200:---:200:404:---:404:---:200:---:---:---:---:---:---:404:+++::^$:VNC HTTPD (RFB 003.003)
+++:200:---:200:200:---:---:---:---:404:+++:200:---:---:---:---:---:---:+++:+++::^$:VNC HTTPD
# VNC Server Enterprise Edition/E4.4.0 (r12094)
# RealVNC-Xvnc/E4.4.2 (r13160)
# VNC Server Personal Edition/P4.4.2 (r13117)
# VNC Server Enterprise Edition/E4.4.3 (r16583)
# VNC Server Enterprise Edition/E4.5 (r21561)
200:400:501:200:200:501:400:400:400:404:404:200:501:501:501:501:501:501:400:400:RealVNC-Xvnc:^(VNC Server (Personal|Enterprise) Edition|RealVNC-Xvnc)/[EP]4\.[45]:RealVNC-Xvnc/4.4-4.5 [VNC Server Enterprise/Personal Edition]
#
##400:501:200:200:501:200:400:400:404:+++:200:501:501:501:501:501:501:+++::RealVNC/4.0
+++:400:501:200:200:501:200:400:400:404:404:200:501:501:501:501:501:501:404:+++:::RealVNC/4.0
400:400:501:200:200:501:200:400:400:404:404:200:501:501:501:501:501:501:404:404:::RealVNC/4.0
400:400:501:200:200:501:200:400:400:404:404:200:501:501:501:501:501:501:400:400:::RealVNC/4.0
#
HTM:404:200:HTM:HTM:HTM:404:404:404:404:404:200:404:501:501:501:501:501:404:---:VLC:^$:VLC Media Player 0.8.5
# VLC 0.8.6e on Gentoo / VLC 0.8.6d on Windows
HTM:404:200:HTM:HTM:HTM:404:404:404:404:404:200:404:501:501:501:501:501:404:404:VLC:^$:VLC Media Player 0.8.6
+++:404:501:404:404:501:501:501:404:404:302:404:302:501:501:501:501:501:404:+++:::VPOP3 Mail Http Server [2.1.0h]
# Found on a Wago Ethernet Buscoupler 750-342
# http://www.nessus.org/u?50093e6e
+++:404:501:200:200:501:501:501:400:404:+++:200:404:501:501:501:501:501:+++:+++::^$:WAGO-I/O-System [WAGO 750-342]
#
+++:HTM:400:HTM:HTM:200:200:---:---:400:+++:400:---:403:403:403:403:403:+++:+++:::WALT HTTP Server, v2.11 (22.04.03)
+++:200:204:505:505:505:200:---:---:---:---:400:404:404:404:404:404:404:500:+++::^$:Waterken/3.5
# WDaemon/6.8.4 to WDaemon/9.0.4?
+++:400:501:200:200:200:400:400:400:404:404:200:404:501:501:501:501:501:404:+++:WDaemon:^WDaemon/(6\.[89]|7\.[0-9]|8\.[01]|9\.0).[0-9]:WDaemon/6.8.4 to 9.0.4
+++:200:404:200:200:200:404:404:404:404:404:200:404:404:404:404:404:404:400:+++:::Web Crossing/5.0
# Webfs (another gizmo?)
+++:400:400:200:400:400:400:400:400:400:+++:+++:501:501:400:400:400:400:+++:+++:::webfs/1.20
# www-servers/webfs-1.21-r1 on Gentoo Linux
400:400:400:200:400:400:400:400:400:400:400:200:501:501:400:400:400:400:200:404:::webfs/1.21
+++:400:405:200:200:405:405:405:405:404:---:---:400:400:405:405:405:405:+++:+++::^Web Server/4\.10:DLink-604
# DLink Di604 firmware 1.62 (European version) - very fragile (killed by POST)
+++:200:200:200:200:200:404:404:404:200:404:200:+++:404:404:404:404:404:+++:+++::^$:DLink Di604 firmware 1.62 (European version)
# Webmin
+++:---:200:200:200:200:200:200:200:200:+++:+++:200:200:200:200:200:200:200:+++:::MiniServ/0.01 [Webmin]
# Webmin 1.400-r1 on Gentoo - more precise signature
---:---:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:200:::MiniServ/0.01 [Webmin 1.400]
# SuSe Linux 8.0 Standard - Webmin 1.140 installed in https mode on port 10000
+++:---:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:404:+++:+++:::MiniServ/0.01 [Webmin 1.140]
# WebLogic - note: << : >> in signature were replaced by << . >>
200:---:200:200:200:---:---:---:---:200:200:200:+++:---:200:200:---:---:+++:+++:WebLogic/4::WebLogic 4.5.2 06/01/2000 22.30.43 #71928
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:403:+++:WebLogic/6::WebLogic WebLogic Server 6.1 SP4  11/08/2002 21.50.43 #221641
+++:---:200:200:200:501:200:---:---:302:404:400:200:405:405:200:501:501:403:+++:WebLogic/7::WebLogic WebLogic Server 7.0 SP2  Sun Jan 26 23.09.32 PST 2003 234192
+++:---:200:200:200:200:200:---:---:200:404:200:200:200:200:200:200:200:200:+++:WebLogic/8::WebLogic Portal 8.1 Thu Jul 10 20:09:22 PDT 2003 84868
# Odd signature without Server field
# ---:---:200:200:200:200:200:---:---:200:404:200:200:200:200:200:200:200:200:200:::
+++:400:200:200:200:501:200:---:---:404:302:400:+++:405:405:501:501:501:+++:+++:WebLogic/8:^$:BEA weblogic 8.1 SP4
# D-Link
+++:200:405:200:200:501:405:405:404:404:405:200:404:405:405:405:405:405:501:+++::^$:Web Server/1.0 [might be D-Link print server]
+++:200:405:200:200:501:405:405:404:404:405:200:+++:405:405:405:405:405:+++:+++:::Web Server/1.0 [D-Link DP-101P+ Print Server]
# WAS - probably not very reliable banners, as 408 = TimeOut
# 408:200:408:200:200:200:408:200:200:408:408:408:200:408:408:+++:408:200:200:200:200:200:200:200:+++:WebSphere Application Server/5.0
# More precise
+++:408:408:200:200:200:408:408:408:408:408:408:200:200:200:200:200:200:+++:+++:::WebSphere Application Server/4.0
+++:408:408:200:200:200:408:408:408:408:408:408:404:405:405:200:501:501:200:+++:::WebSphere Application Server/5.0
+++:HTM:HTM:200:200:200:HTM:HTM:HTM:HTM:HTM:400:200:200:200:200:200:200:200:+++:::WebSphere Application Server/4.0
# Less precise
+++:HTM:HTM:200:200:200:HTM:HTM:HTM:HTM:HTM:400:+++:200:200:200:200:200:+++:+++:::WebSphere Application Server/5.1
# IBM WebSphere Application Server - ND, 6.0.2.15 -- Build Number: cf150636.04 -- Build Date: 9/5/06 -- Win 2k3 Enterprise Service Pack 2
505:505:404:VER:505:VER:400:400:400:400:400:200:404:404:404:404:404:404:404:404:::WebSphere Application Server/6.0
# 4D WebStar
+++:HTM:xxx:200:200:200:---:---:---:404:404:200:404:xxx:xxx:xxx:xxx:xxx:200:+++:WebSTAR/3::WebSTAR/3.0 ID/64110
+++:200:---:200:200:---:---:---:---:404:404:200:---:---:---:---:---:---:+++:+++:WebSTAR/4::WebSTAR/4.0(SSL)
+++:200:---:200:200:---:---:---:---:200:404:200:200:---:---:---:---:---:+++:+++:WebSTAR/4::WebSTAR/4.4(SSL)
# More precise
+++:200:---:200:200:---:---:---:---:200:404:200:200:---:---:---:---:---:200:+++:WebSTAR/4::WebSTAR/4.3(SSL) ID/72870
+++:200:---:200:200:---:---:---:---:404:404:200:404:---:---:---:---:---:404:+++:WebSTAR/5::WebSTAR/4.5(SSL)
# WebSTAR/4.5(SSL) ID/71089
# WebSTAR/4.5(SSL) ID/75942
+++:200:---:200:200:---:---:---:---:404:404:200:404:---:---:---:---:---:200:+++:WebSTAR/4:^WebSTAR/4\.5\(SSL\) ID/7[1-5][0-9]{3}:WebSTAR/4.5(SSL) ID/71089-75942
# WebSTAR/4.2(SSL) ID/72840
# WebSTAR/4.5(SSL) ID/78655
+++:200:405:200:200:200:---:---:---:200:200:200:200:405:405:405:405:405:200:+++:WebSTAR/4:^WebSTAR/4\.[25]\(SSL\):WebSTAR/4.2-5
+++:200:200:200:200:200:---:---:---:200:200:200:200:200:200:200:---:---:200:+++:WebSTAR/4::WebSTAR/4.5(SSL) ID/72838
+++:200:405:200:200:200:---:---:---:404:404:200:404:405:405:405:---:405:200:+++:WebSTAR/4::WebSTAR/4.5 Beta/1(SSL) ID/70232
#
+++:200:405:200:200:200:---:---:---:404:404:200:404:405:405:405:---:---:---:+++:::WebSTAR NetCloak
+++:200:404:200:200:200:---:---:---:404:404:200:404:404:404:404:xxx:xxx:200:+++:::WebSTAR NetCloak
# Lasso/6.0
+++:---:200:200:500:---:500:---:---:500:500:500:404:405:405:405:405:405:500:+++:4D_WebSTAR/5:^4D_WebSTAR_S/5\.[23]\.[0124] \(MacOS X\):4D_WebSTAR_S/5.2.4-5.3.2 (MacOS X)
+++:---:200:200:200:---:200:---:---:404:404:200:404:405:405:405:405:405:200:+++:4D_WebSTAR/5:^4D_WebSTAR_S/5\.[23]\.[1234] \(MacOS X\):4D_WebSTAR_S/5.2.3-5.3.2 (MacOS X)
+++:---:200:200:200:---:200:---:---:404:404:200:404:401:401:401:401:401:200:+++:4D_WebSTAR/5:^4D_WebSTAR_S/5\.3\.[12] \(MacOS X\):4D_WebSTAR_S/5.3.1-2 (MacOS X)
+++:---:501:200:400:400:---:---:---:500:500:500:404:405:405:501:501:501:500:+++:4D_WebSTAR/5::4D_WebSTAR_S/5.3.1 (MacOS X)
+++:---:200:200:302:---:302:---:---:404:404:302:404:405:405:405:405:405:---:+++:4D_WebSTAR/5::4D_WebSTAR_S/5.3.1 (MacOS X)
+++:---:200:200:500:---:500:---:---:500:500:500:404:401:401:401:401:401:500:+++:4D_WebSTAR/5::4D_WebSTAR_S/5.3.2 (MacOS X)
#
401:---:501:401:401:---:---:---:401:401:302:---:404:501:501:501:---:---:401:403:webWethods:^$:webWethods broker service
# wildfly-8.1.0.Final on RHEL 6.5
HTM:400:405:VER:VER:VER:200:400:xxx:404:404:200:404:405:405:405:405:405:200:404:::wildfly-8.1.0
# wildfly-8.0.0.CR1 on RHEL 6.5
---:400:405:VER:VER:VER:200:400:400:404:404:200:404:405:405:405:405:405:200:400:::wildfly-8.0.0.CR1
#
+++:HTM:200:HTM:HTM:501:200:HTM:HTM:200:+++:400:404:501:501:200:501:501:+++:+++:::WN/2.2.10
# Web management from Tinix
+++:VER:302:302:VER:VER:VER:VER:VER:VER:VER:VER:302:302:302:302:302:302:VER:+++:::Weaver/4.0b #2
# WN/2.4.6 on my Linux Gentoo box
+++:HTM:200:505:505:501:200:HTM:HTM:200:400:400:200:200:200:200:501:501:200:+++:::WN/2.4.6 [broken conf - no index]
+++:HTM:200:505:505:501:200:HTM:HTM:200:400:400:404:404:404:200:501:501:200:+++:::WN/2.4.6
#
+++:200:404:200:200:200:200:200:200:302:404:200:404:404:404:404:404:404:404:+++:::Xeneo/2.2
+++:200:501:200:200:200:501:501:501:200:+++:200:501:501:501:501:501:501:+++:+++:::XES 8830 WindWeb/1.0
+++:HTM:400:200:HTM:---:HTM:HTM:HTM:400:+++:400:100:100:200:200:200:200:+++:+++:::Xerox_MicroServer/Xerox11
+++:---:501:505:505:400:---:---:---:200:501:400:400:501:501:501:501:501:+++:+++::^$:Xerox DocuColor 1632 Color Copier/Printer
+++:---:---:---:---:VER:---:---:---:404:---:200:+++:---:---:---:---:---:+++:+++::^$:Xerox Phaser 3450 DN
+++:200:501:404:404:404:200:501:501:200:404:200:400:403:403:501:403:501:+++:+++::^Xitami$:Xitami v2.4d9
302:200:501:404:404:404:200:501:501:200:404:200:400:403:403:501:403:501:200:413::^Xitami$:Xitami v2.4d11
+++:200:501:403:403:403:200:501:501:200:404:200:400:403:403:501:403:501:200:+++::^Xitami$:Xitami v2.4d7
# Unknown version, but <= 2.4d9
+++:400:501:501:501:400:400:400:400:200:404:400:400:403:403:501:403:501:200:+++:::Xitami
# Conflicting
400:400:501:501:501:400:400:400:400:200:404:400:400:403:403:501:403:501:200:413::^Xitami$:Xitami v2.5c2
# dev-dotnet/xsp-2.0
# X-AspNet-Version: 1.1.4322
200:200:405:VER:VER:VER:500:500:500:200:200:200:200:200:200:200:200:200:200:404:::Mono.WebServer/0.1.0.0 Unix
# YaWS, a web server written in Erlang; I got those banners
# Yaws/1.01 Yet Another Web Server
# Yaws/1.22 Yet Another Web Server
+++:200:200:---:---:---:200:---:---:404:---:200:---:---:---:---:---:---:---:+++::Yaws/1\.[02][12] Yet Another Web Server:Yaws/1.01 or Yaws/1.22
# New version, new behaviour...
+++:200:200:---:400:400:200:400:400:404:---:200:---:501:501:501:501:501:200:+++:::Yaws/1.30 Yet Another Web Server
+++:200:200:---:400:400:200:400:400:404:403:200:---:501:501:501:501:501:200:+++:::Yaws/1.31 Yet Another Web Server
# Zeroo is another gizmo which does not even implement full HTTP protocol
+++:200:404:200:200:200:404:404:200:404:404:200:404:404:404:404:404:404:200:+++::^$:Zeroo 1.5
#
+++:HTM:501:400:400:501:404:400:400:400:400:400:404:404:501:501:501:501:404:+++:::Zeus/3.3
+++:HTM:501:400:400:501:404:---:---:404:---:404:404:404:501:501:501:501:404:+++:::Zeus/3.3
+++:HTM:501:400:400:501:200:400:400:200:200:400:200:200:501:501:501:501:200:+++:::Zeus/3.3
+++:HTM:501:400:400:501:200:400:400:400:400:400:404:404:501:501:501:501:200:+++:::Zeus/3.3
+++:HTM:501:400:400:501:200:400:400:400:400:200:404:404:501:501:501:501:200:+++:::Zeus/3.3
+++:xxx:501:400:400:501:200:400:400:400:400:400:404:404:501:501:501:501:200:+++:::Zeus/3.3
# Zeus/4.0
# Zeus/4.3
+++:HTM:400:400:400:501:200:400:400:400:400:400:405:405:501:501:501:501:200:+++:Zeus/4:^Zeus/4\.[0-3]:Zeus/4.0-4.3
+++:HTM:400:400:400:501:404:400:400:400:400:400:405:405:405:405:405:501:404:+++:Zeus/4::Zeus/4.1
+++:HTM:400:400:400:501:403:400:400:400:400:400:405:405:405:405:405:501:403:+++:Zeus/4::Zeus/4.1
+++:HTM:400:400:400:501:404:400:400:404:404:400:405:405:405:405:405:501:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:501:404:500:500:400:400:404:405:405:405:405:405:501:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:501:404:500:500:400:400:404:405:403:403:405:405:501:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:501:404:400:400:400:400:400:405:403:403:405:405:501:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:---:---:---:---:404:404:404:405:405:405:405:405:---:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:400:400:500:500:404:404:404:405:405:405:405:405:501:404:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:501:200:400:400:400:400:400:405:405:405:405:405:501:200:+++:Zeus/4::Zeus/4.2
+++:HTM:400:400:400:501:200:500:500:400:400:200:405:405:501:501:501:501:200:+++:Zeus/4::Zeus/4.3
+++:HTM:400:400:400:501:404:400:400:403:403:400:405:405:501:501:501:501:404:+++:Zeus/4::Zeus/4.3
# Zeus web server from ZXTM Virtual machine 2006-02-27-1
# I don't know why the web server is identified as '4_3' and
# the administration server as '4_4'
+++:HTM:400:400:400:501:200:400:400:400:400:200:405:405:405:405:405:501:200:+++:::Zeus/4_3 [ZXTM Virtual machine 2006-02-27-1]
+++:HTM:400:400:400:501:302:400:400:400:400:400:302:302:302:302:302:501:302:+++:::Zeus/4_4 [administration page]
#
+++:HTM:HTM:200:HTM:200:400:400:HTM:200:403:400:404:HTM:HTM:HTM:HTM:HTM:200:+++:::ZazouMiniWebServer v1.0.0-rc2
# Zope/(Zope 2.5.1 (OpenBSD package zope-2.5.1p1)
# Zope/(Zope2.7.0, python 2.3.3, win32) ZServer/1.1 Plone/2.0-final
# And also Linux Gentoo, according to some old tests? I m not sure any more
+++:500:404:VER:400:400:400:400:400:404:404:200:404:404:404:404:404:404:200:+++:Zope/2:^Zope/\(Zope 2\.[57]\.:Zope/(Zope 2.5.1-2.7.0)
# Zope/(Zope 2.6.2 (source release, python 2.1, linux2), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.6.1 (source release, python 2.1, linux2), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.6.1 (binary release, python 2.1,linux2-x86), python 2.1.3, linux2) ZServer/1.1b1
# Zope/(Zope 2.5.1 (OpenBSD package zope-2.5.1p1) [yes the same server can give a different signature!]
# Zope/(Zope 2.7.4-0, python 2.3.4, linux2) ZServer/1.1
+++:500:404:VER:400:400:400:400:400:404:404:200:404:401:404:404:404:404:200:+++:Zope/2:^Zope/\(Zope 2\.[5-7]\.:Zope 2.5.to 2.7
+++:500:404:VER:400:400:400:400:400:404:404:200:200:403:404:404:404:200:200:+++:Zope/2::Zope/(Zope 2.7.0, python 2.3.4, linux2) ZServer/1.1
# Zope/(Zope 2.8.6-final, python 2.3.5, win32) ZServer/1.1 [?]
# Zope/(Zope 2.9.8-final, python 2.4.4, linux2) ZServer/1.1
# Zope/(Zope 2.10.6-final, python 2.4.4, linux2) ZServer/1.1
400:500:404:VER:400:400:400:400:400:404:404:200:404:401:401:404:404:200:200:404:Zope/2.8:^Zope/\(Zope 2\.([89]|10)\.[68]-final, python 2\.[34]\.[45], (linux2|win32)\) ZServer/1.1:Zope/(Zope 2.8.6-2.10.6, python 2.3 or 2.4, linux2 or win32) ZServer/1.1
# Web Server/4.10 ??
# RomPager/4.07 UPnP/1.0
# ZyXEL-RomPager/3.02
+++:400:405:200:200:405:405:405:405:404:404:400:400:400:405:405:405:405:400:+++:ZyXEL-RomPager:^(ZyXEL-)?RomPager/[34]\.[01][27]( UPnP/1\.0)?:ZyXEL-RomPager/3.02 or 4.10
#
+++:400:501:VER:400:404:400:400:400:400:400:404:404:501:501:501:501:501:404:+++:::0W/0.6e
+++:400:501:VER:400:404:400:400:400:400:400:404:400:501:501:501:501:501:404:+++:::0W/0.7e [no /]
+++:400:501:VER:400:200:400:400:400:400:400:200:400:501:501:501:501:501:200:+++:::0W/0.7
################################
#### Unconfirmed signatures ####
################################
200:200:404:200:---:---:200:---:---:---:---:200:404:404:404:404:---:404:404:404:::2wire Gateway
+++:400:405:200:200:405:405:405:405:200:200:400:400:405:405:405:405:405:400:+++:::Allegro-Software-RomPager/3.03
400:400:200:401:401:405:405:405:405:404:404:400:400:405:405:200:405:405:400:400:::Allegro-Software-RomPager/3.10
#
HTM:HTM:200:200:400:501:200:HTM:HTM:200:404:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix)::Apache/1.3 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.8d AuthPG/1.3 FrontPage/5.0.2.2635
HTM:HTM:200:200:400:501:404:HTM:HTM:404:404:400:404:405:404:200:404:501:404:404:Apache/1.3 (Unix)::Apache/1.3 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.8d AuthPG/1.3 FrontPage/5.0.2.2635
HTM:HTM:200:200:200:403:200:HTM:HTM:400:400:400:200:405:200:200:200:403:200:403:Apache/1.3 (Unix)::Apache/1.3.4 (Unix)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.9 Ben-SSL/1.37 (Unix) Debian/GNU PHP/3.0.18
# Apache/1.3.9 (FreeBSD) PHP/3.0.12 mod_ssl/2.4.1 OpenSSL/0.9.4 rus/PL28.17
# Apache/1.3.12 (Unix) mod_perl/1.24 PHP/4.0.0
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(9|1[0-2]):Apache/1.3.9-1.3.12 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.12:IBM_HTTP_Server/1.3.12.7 Apache/1.3.12 (Unix)
505:400:404:505:505:302:400:400:400:302:302:400:404:404:404:404:404:404:302:302:Apache/1.3 (Unix)::Apache/1.3.14 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.1 OpenSSL/0.9.6 PHP/4.1.2
HTM:HTM:403:200:200:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.19 (Unix)  (SuSE/Linux)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:502:405:502:200:502:501:403:403:Apache/1.3 (Unix)::Apache/1.3.20 (Unix) mod_perl/1.25
HTM:HTM:200:200:400:400:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
HTM:HTM:200:200:400:400:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:302:Apache/1.3 (Unix)::Apache/1.3.26 (Linux/SuSE) mod_ssl/2.8.10 OpenSSL/0.9.6g PHP/4.2.2 mod_throttle/3.1.2
+++:HTM:200:200:400:400:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2 mod_jk/1.1.0
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:302:302:302:200:302:302:200:302:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux mod_perl/1.26
+++:HTM:403:403:400:400:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Darwin) PHP/4.0.6
HTM:HTM:200:403:400:501:200:HTM:HTM:400:400:400:406:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.36 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.2 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.27 OpenSSL/0.9.6b
+++:xxx:200:200:400:400:200:xxx:xxx:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
+++:HTM:200:401:400:400:401:HTM:HTM:400:400:400:401:405:404:200:404:501:401:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:401:401:200:401:401:200:404:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) mod_accounting/0.6 PHP/4.3.4 DAV/1.0.3 mod_ssl/2.8.10 OpenSSL/0.9.6g
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:302:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) AuthMySQL/2.20 PHP/4.1.2 mod_gzip/1.3.19.1a mod_ssl/2.8.9 OpenSSL/0.9.6g
HTM:HTM:403:403:400:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.36 (Unix) mod_gzip/1.3.26.1a mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.2 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.27 OpenSSL/0.9.6b
HTM:HTM:200:200:400:302:302:HTM:HTM:400:400:400:200:200:200:200:200:200:302:302:Apache/1.3 (Unix)::Apache/1.3.34 (Unix) mod_auth_pam/1.0a FrontPage/5.0.2.2634 mod_throttle/3.1.2 mod_ssl/2.8.25 OpenSSL/0.9.7e
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:200:200:200:200:200:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7d
+++:xxx:200:200:400:400:200:HTM:xxx:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:405:200:200:200:501:403:403:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
HTM:HTM:403:200:400:400:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) PHP/4.3.6 mod_ssl/2.8.10 OpenSSL/0.9.6g
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) mod_ssl/2.8.10 OpenSSL/0.9.6c
# Apache/1.3.26 (Unix) mod_throttle/3.1.2
# Apache/1.3.26 (Unix) PHP/4.3.0 mod_perl/1.24 ApacheJserv/1.1.2
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:403:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:HTM:411:411:302:200:302:501:HTM:HTM:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_watch/2.0 mod_throttle/3.1.2 mod_gzip/1.3.19.1a mod_auth_pam/1.0a mod_ssl/2.8.11 OpenSSL/0.9.6j mod_perl/1.25
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:500:404:200:404:405:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) mod_gzip/1.3.26.1a PHP/4.3.1 DAV/1.0.3
+++:---:200:200:400:501:200:HTM:---:400:400:400:404:405:404:501:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) PHP/5.0.5 mod_ssl/2.8.16 OpenSSL/0.9.7g
XML:XML:200:200:400:501:200:HTM:XML:400:400:400:302:405:302:200:302:501:200:302:Apache/1.3 (Unix)::Apache/1.3.33 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:500:404:Apache/1.3 (Unix)::Apache/1.3.33 (Unix)
# Apache/1.3.33 (Unix) PHP/4.4.0
# Apache/1.3.33 (Unix) PHP/4.3.11
HTM:HTM:200:200:400:501:302:HTM:HTM:400:400:400:302:405:302:200:302:501:302:302:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4
HTM:HTM:200:200:400:500:500:HTM:HTM:400:400:400:404:405:404:200:404:501:500:404:Apache/1.3 (Unix)::Apache/1.3.33 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:302:302:400:302:302:302:200:302:501:200:302:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7d mod_jk/1.2.10 PHP/5.1.6
HTM:HTM:200:200:400:200:200:HTM:HTM:200:200:400:200:200:200:200:200:200:200:500:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_perl/1.29 mod_ssl/2.8.22 OpenSSL/0.9.7a
+++:HTM:403:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) PHP/4.4.4
HTM:HTM:403:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7d PHP/4.4.4 FrontPage/5.0.2.2510
# Apache/1.3.29 (Unix) FrontPage/5.0.2.2510 mod_gzip/1.3.26.1a mod_ssl/2.8.16 OpenSSL/0.9.7a-p1
# Apache/1.3.34 (Unix) FrontPage/5.0.2.2623
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:403:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-4]) \(Unix\) FrontPage/5\.0\.2:Apache/1.3.29-1.3.34 (Unix) FrontPage/5.0.2
HTM:HTM:200:200:400:501:302:HTM:HTM:302:302:400:302:302:302:200:302:302:302:302:Apache/1.3 (Unix)::Apache/1.3.36 (Unix) mod_ssl/2.8.27 OpenSSL/0.9.7e-p1 PHP/4.4.2 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:302:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
HTM:HTM:200:406:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_fastcgi/2.4.2 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:HTM:200:200:400:301:301:HTM:HTM:400:400:400:404:403:403:200:404:501:301:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_gzip/1.3.26.1a mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:HTM:200:200:400:403:200:HTM:HTM:400:301:400:404:405:403:200:403:500:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_accel/1.0.34
HTM:HTM:200:200:400:501:200:HTM:HTM:404:301:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) FrontPage/5.0.2.2635 mod_ssl/2.8.28 OpenSSL/0.9.7l
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:404:501:500:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_bwlimited/1.4 mod_log_bytes/1.2 mod_ssl/2.8.28 OpenSSL/0.9.7e FrontPage/5.0.2.2635
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:403:501:403:403:Apache/1.3 (Unix)::Apache/1.3.29 (Unix)
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7j
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7g
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:501:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7
HTM:HTM:200:200:400:302:302:HTM:HTM:400:400:400:403:405:404:200:404:501:302:302:Apache/1.3 (Unix)::Apache/1.3.29 Sun Cobalt (Unix) mod_jk mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.2.3 mod_auth_pam_external/0.1 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.29 Sun Cobalt (Unix) PHP/4.3.11 Chili!Soft-ASP/3.6.2 mod_ssl/2.8.16 OpenSSL/0.9.6m mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.29 Sun Cobalt (Unix) mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.0.6 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.29 Sun Cobalt (Unix) mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.29 Sun Cobalt (Unix) Chili!Soft-ASP/3.6.2 mod_ssl/2.8.16 OpenSSL/0.9.6m PHP/4.3.8 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.37 (Unix) PHP/4.4.4 FrontPage/5.0.2.2623 mod_ssl/2.8.28 OpenSSL/0.9.6c
# Apache/1.3.29 Sun Cobalt (Unix)
HTM:HTM:200:200:400:302:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:302:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-7]):Apache/1.3.29-1.3.37 (Unix)
+++:HTM:200:200:HTM:400:200:HTM:HTM:400:xxx:400:404:405:404:200:404:501:200:+++:Apache/1.3 (OpenVMS)::Apache/1.3.26 (OpenVMS) PHP/4.3.2 mod_ssl/2.8.10 OpenSSL/0.9.7d
HTM:HTM:403:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
+++:xxx:200:200:400:501:200:HTM:xxx:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
400:400:400:200:400:400:200:400:400:400:400:200:411:411:404:200:404:400:200:404:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_throttle/3.1.2 mod_ssl/2.8.12 OpenSSL/0.9.6b PHP/4.1.2
HTM:HTM:200:200:400:501:404:HTM:HTM:400:400:400:404:403:403:200:404:501:404:403:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_ldap_userdir/0.9 FrontPage/5.0.2.2510 mod_gzip/1.3.26.1a mod_ssl/2.8.16 OpenSSL/0.9.7m
HTM:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:200:200:Apache/1.3 (Unix)::Apache/1.3.31 (Unix)
# Apache/1.3.29 (Unix)
# Apache/1.3.33 (Unix) Sun-ONE-ASP/4.0.0 PHP/5.0.4 FrontPage/5.0.2.2510 mod_ssl/2.8.22 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix) PHP/4.3.10
HTM:HTM:200:200:400:501:404:HTM:HTM:400:400:400:404:405:404:200:404:501:404:404:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-3]):Apache/1.3.29-1.3.33 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:302:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) mod_jk/1.1.0 PHP/4.3.10-16 mod_ssl/2.8.22 OpenSSL/0.9.7e mod_perl/1.29
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.4.0-4 mod_ssl/2.8.24 OpenSSL/0.9.8
# Apache/1.3.34 (Debian) mod_gzip/1.3.26.1a PHP/5.2.0-8+etch4 DAV/1.0.3 mod_perl/1.29
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.3[34]:Apache/1.3.33-1.3.34 (Linux)
HTM:HTM:200:200:400:302:302:HTM:HTM:302:302:400:404:405:404:200:404:501:302:302:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.4.0-0.dotdeb.0
400:400:400:200:400:400:400:400:400:400:400:200:404:404:404:200:404:400:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix)
HTM:HTM:403:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7d PHP/4.3.10 mod_perl/1.29 FrontPage/5.0.2.2510
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:302:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) PHP/4.3.10 mod_ssl/2.8.18 OpenSSL/0.9.7b
+++:---:200:200:400:200:200:---:---:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) PHP/5.0.4
# More precise
---:---:200:200:400:200:200:---:---:400:400:400:404:405:404:200:404:501:200:404:::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.8e
+++:HTM:200:200:400:501:200:HTM:HTM:200:400:400:200:200:200:200:200:200:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:403:403:200:200:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) FrontPage/5.0.2.2623 mod_ssl/2.8.19 OpenSSL/0.9.7d mod_perl/1.26 PHP/4.1.2
# Apache/1.3.31 (Unix) mod_perl/1.29 mod_ssl/2.8.19 OpenSSL/0.9.7a
# Apache/1.3.33 (Unix)
# Apache/1.3.33 (Unix) FrontPage/5.0.2.2623 PHP/5.0.4
HTM:HTM:200:200:400:501:404:HTM:HTM:400:400:400:404:403:403:200:404:501:404:404:Apache/1.3 (Unix):Apache/1\.3\.3[1-3]:Apache/1.3.31-1.3.33 (Unix)
+++:HTM:200:401:400:501:401:HTM:HTM:400:400:400:401:401:401:403:401:405:401:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) DAV/1.0.3 mod_ssl/2.8.24 OpenSSL/0.9.7l PHP/4.4.4 mod_perl/1.29
+++:XML:200:200:400:501:200:HTM:XML:400:400:400:404:403:403:200:403:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18 mod_ssl/2.8.22 OpenSSL/0.9.7e
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:403:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) PHP/5.1.1 PHP/4.4.1
# Apache/1.3.33 (Unix)
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18
# Apache/1.3.33 (Unix) PHP/4.3.11 mod_ssl/2.8.22 OpenSSL/0.9.7e
HTM:HTM:200:200:400:501:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Unix):Apache/1\.3\.33:Apache/1.3.33 (Unix)
+++:HTM:200:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:403:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4.3.10
+++:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-16 mod_ssl/2.8.24 OpenSSL/0.9.7g
# More precise:
# Apache/1.3.34 (Debian) PHP/5.2.0-8+etch7
# Apache/1.3.34 (Debian) PHP/5.2.0-8+etch10
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:405:404:200:404:501:200:200:Apache/1.3 (Unix)::Apache/1.3.34 (Debian) PHP/5.2.0-8
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:404:404:403:404:404:404:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_perl/1.29
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:403:200:403:501:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) mod_ssl/2.8.22 OpenSSL/0.9.7e PHP/4.4.0-0.dotdeb.0 mod_perl/1.29 DAV/1.0.3
+++:---:200:200:400:501:200:HTM:---:400:400:400:404:403:403:200:403:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.34 (Debian) PHP/4.4.4-7 mod_perl/1.29
HTM:HTM:200:200:400:200:200:HTM:HTM:200:400:400:200:200:200:200:200:200:200:200:Apache/1.3 (Win32)::Apache/1.3.27 (Win32) PHP/4.3.4 [suspicious]
# Apache/1.3.29 (Unix) mod_gzip/1.3.26.1a mod_perl/1.29 mod_ssl/2.8.16 OpenSSL/0.9.7g
# Apache/1.3.33 (Darwin) PHP/5.0.4 mod_ssl/2.8.24 OpenSSL/0.9.7i
+++:XML:200:200:400:501:200:HTM:XML:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-3]) \((Darwin|Unix)\):Apache/1.3.28-33 (Unix)
+++:HTM:200:200:400:501:---:---:---:400:400:400:404:401:401:403:401:405:---:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) mod_jk/1.2.6 DAV/1.0.3 mod_ssl/2.8.24 OpenSSL/0.9.7l
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:406:406:406:200:406:406:200:404:Apache/1.3 (Unix)::Apache/1.3.31 (Unix) mod_perl/1.29 PHP/4.3.7
HTM:HTM:200:200:400:500:200:HTM:HTM:400:400:400:404:403:403:200:501:501:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-16 mod_ssl/2.8.9 OpenSSL/0.9.6g mod_perl/1.29 mod_jk/1.1.0
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:403:403:Apache/1.3 (Unix)::Apache/1.3.33 Ben-SSL/1.55 (Unix) PHP/4.3.10
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:403:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.8d PHP/4.4.7
# Apache/1.3.33 (Darwin) mod_ssl/2.8.24 OpenSSL/0.9.7i PHP/4.4.1 mod_perl/1.26
# Apache/1.3.33 (Darwin) mod_jk/1.2.6 PHP/5.1.4 LittleDutchMoose/v10.3(Build 2A82) mod_ssl/2.8.24 OpenSSL/0.9.7i
+++:HTM:200:200:400:501:---:---:---:400:400:400:404:405:404:403:404:501:---:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:401:401:403:401:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) mod_jk/1.2.6 DAV/1.0.3 mod_ssl/2.8.24 OpenSSL/0.9.7i PHP/4.4.1
HTM:HTM:200:200:400:403:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.27 (Linux/SuSE) FrontPage/4.0.4.3 PHP/4.3.1 mod_perl/1.27 mod_ssl/2.8.12 OpenSSL/0.9.6i
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:403:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/4.4.6 FrontPage/5.0.2.2635 mod_gzip/1.3.26.1a
XML:XML:200:200:400:200:200:XML:XML:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3(Unix):Apache/1\.3\.3[3-7] \(Unix|.*Linux.*\):Apache/1.3.33-1.3.37 (Unix)
XML:XML:200:200:400:501:200:HTM:XML:400:400:400:404:302:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4.4.2 DAV/1.0.3 mod_ssl/2.8.22 OpenSSL/0.9.7d
HTM:HTM:200:200:400:302:302:HTM:HTM:302:302:400:302:405:302:200:302:501:302:302:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18
HTM:HTM:200:200:400:501:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:404:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18
400:400:400:200:400:400:400:400:400:400:400:200:404:405:404:200:404:400:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix)
HTM:HTM:200:200:400:500:500:HTM:HTM:400:400:400:404:405:404:200:404:501:500:300:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) [w/ PHP/4.4.7]
HTM:HTM:403:200:400:501:404:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.34 (Unix) PHP/4.4.2
HTM:HTM:200:200:400:404:404:HTM:HTM:400:400:400:200:200:200:200:200:200:404:404:Apache/1.3 (Unix)::Apache/1.3.34 (Unix)  mod_thebbs/3.1415926
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.8a PHP-CGI/0.1b
# Apache/1.3.37 (Unix) PHP/5.2.2 mod_perl/1.29 mod_ssl/2.8.28 OpenSSL/0.9.8d
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
HTM:HTM:200:200:400:501:302:HTM:HTM:400:400:400:302:405:302:200:302:501:302:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/4.4.6 rus/PL30.22
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:411:411:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/5.1.0RC1 mod_perl/1.30
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7a PHP/4.3.4 mod_perl/1.27 FrontPage/5.0.2.2510
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7a PHP/4.4.5 mod_perl/1.29 FrontPage/5.0.2.2510
HTM:HTM:403:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-7]):Apache/1.3.29-1.3.37 (Unix)
# Apache/1.3.33 (Unix) mod_jk/1.2.14 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.11 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) mod_jk/1.2.14 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.3 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:403:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.3[3-7]:Apache/1.3.33-1.3.37 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:406:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.3 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
HTM:HTM:200:503:400:501:200:HTM:HTM:400:400:400:503:404:404:200:404:404:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_throttle/3.1.2 DAV/1.0.3 mod_fastcgi/2.4.2 mod_gzip/1.3.26.1a PHP/4.4.7 mod_ssl/2.8.22 OpenSSL/0.9.7e
HTM:HTM:200:403:400:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/5.1.4 mod_ssl/2.8.28 OpenSSL/0.9.7f mod_perl/1.29 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:VER:VER:VER:200:VER:VER:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b [w/ PHP/4.3.11]
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:406:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.37:Apache/1.3.37 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/4.4.7 mod_ssl/2.8.28 OpenSSL/0.9.7a FrontPage/5.0.2.2635
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:500:500:500:200:500:500:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7a PHP/4.4.4 mod_perl/1.29 FrontPage/5.0.2.2510
# Apache/1.3.37 (Unix) PHP/5.2.2 mod_ssl/2.8.28 OpenSSL/0.9.7a mod_perl/1.29 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
# Apache/1.3.33 (Unix) mod_fastcgi/2.4.2 mod_jk/1.2.14 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.3.10 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7a
# Apache/1.3.37 (Unix) mod_gzip/1.3.26.1a mod_auth_passthrough/1.8 mod_log_bytes/1.2 PHP/4.4.6 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a mod_bwlimited/1.4
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/1.3 (Unix):Apache/1\.3\.3[3-7]:Apache/1.3.33-1.3.37 (Unix)
HTM:HTM:200:503:400:501:200:HTM:HTM:400:400:400:503:VER:VER:200:VER:VER:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_throttle/3.1.2 DAV/1.0.3 mod_fastcgi/2.4.2 mod_gzip/1.3.26.1a PHP/4.4.7 mod_ssl/2.8.22 OpenSSL/0.9.7e
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4.3.11
# Apache/1.3.27 (Unix)
# Apache/1.3.33 (Darwin) PHP/4.3.6 mod_perl/1.29
xxx:xxx:200:200:400:501:200:HTM:xxx:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.[23][0-9]:Apache/1.3.27-1.3.33 (Unix)
+++:HTM:401:200:400:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin)
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:404:403:404:405:403:+++:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) mod_jk/1.2.6 DAV/1.0.3 mod_ssl/2.8.24 OpenSSL/0.9.7l PHP/4.4.4
+++:XML:200:200:400:501:200:HTM:XML:400:400:400:200:405:200:200:200:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.34 (Debian) mod_perl/1.29
400:400:400:200:400:400:400:400:400:400:400:400:404:405:404:200:404:400:400:400:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_perl/1.26 PHP/4.4.4 AuthMySQL/2.20
HTM:HTM:200:503:400:501:200:HTM:HTM:400:400:400:503:405:VER:200:VER:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_throttle/3.1.2 DAV/1.0.3 mod_fastcgi/2.4.2 mod_gzip/1.3.26.1a PHP/4.4.7 mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.36 (Unix) PHP/4.4.2 mod_ssl/2.8.27 OpenSSL/0.9.7e
# Apache/1.3.37 (Unix) mod_gzip/1.3.26.1a mod_perl/1.29 PHP/4.4.4 with Suhosin-Patch mod_ssl/2.8.28 OpenSSL/0.9.8d
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:405:200:200:200:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.3[67] \(Unix\):Apache/1.3.36-1.3.37 (Unix)
# Apache/1.3.34 (Unix) PHP/4.4.1
# Apache/1.3.37 (Unix) PHP/4.4.3
# Apache/1.3.37 (Unix) PHP/4.4.4
+++:HTM:200:200:400:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:+++:Apache/1.3 (Unix):Apache/1\.3\.3[4-7] \(Unix\) PHP/4\.4\.[1-4]:Apache/1.3.34-37 (Unix) PHP/4.4.1-4.4.4
+++:HTM:404:200:400:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:+++:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.8b PHP/4.4.4
HTM:HTM:200:503:400:501:200:HTM:HTM:400:400:400:503:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_throttle/3.1.2 DAV/1.0.3 mod_fastcgi/2.4.2 mod_gzip/1.3.26.1a PHP/4.4
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:404:405:404:501:200:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18 mod_gzip/1.3.26.1a mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-18
# Apache/1.3.34 (Debian) PHP/4.4.2-1.1 mod_fastcgi/2.4.2 mod_ssl/2.8.25 OpenSSL/0.9.8a mod_perl/1.29
# Apache/1.3.34 (Debian) PHP/4.4.4-6
# Apache/1.3.37 (Unix) mod_gzip/1.3.19.1a PHP/4.4.4
# Apache/1.3.37 (Unix) PHP/5.2.0 mod_perl/1.29
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
+++:---:200:200:400:501:200:HTM:---:400:400:400:404:405:404:200:404:501:200:+++::Apache/1\.3\.3[3-7] \(Unix|[ A-Za-z/-]*Linux\):Apache/1.3.33-37 (Unix) [w/ PHP/4]
HTM:HTM:200:200:400:200:200:HTM:HTM:302:302:400:302:405:302:200:302:501:200:302:Apache/1.3 (Unix)::Apache/1.3.37 ( [NORLUG Edition] Red Hat Linux ) mod_ssl/2.8.28 OpenSSL/0.9.6b PHP/4.4.4 mod_perl/1.29
# Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7a PHP/4.3.11 mod_perl/1.29 FrontPage/5.0.2.2510
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.6b PHP/4.4.4 mod_perl/1.29 FrontPage/5.0.2.2510
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/1.3 (Unix):Apache/1\.3\.3[3-7] \(Unix\):Apache/1.3.33-1.3.37 (Unix)
+++:HTM:200:403:400:403:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
+++:XML:403:200:400:501:200:HTM:XML:400:400:400:404:405:404:200:404:501:200:+++:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
HTM:HTM:200:200:400:503:503:HTM:HTM:503:503:400:404:405:404:200:404:501:503:503:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/4.4.7 mod_ssl/2.8.28 OpenSSL/0.9.7d
+++:XML:200:200:400:200:200:XML:XML:400:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Unix)::Apache/1.3.37 Ben-SSL/1.57 (Unix) PHP/4.3.2
#
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:302:405:302:200:302:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.22 (Win32) PHP/4.1.1
+++:xxx:403:200:200:501:200:HTM:xxx:200:400:400:404:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.22 (Win32)
HTM:HTM:200:200:400:501:200:HTM:HTM:200:400:400:302:405:302:200:302:501:302:302:Apache/1.3 (Win32)::Apache/1.3.27 (Win32)
XML:XML:200:200:400:200:200:XML:XML:404:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32)::Apache/1.3.33 (Win32)
# Apache/1.3.33 (Win32) mod_jk/1.2.0 mod_ssl/2.8.22 OpenSSL/0.9.7d
# Apache/1.3.31 (Win32) PHP/4.3.9
+++:HTM:200:200:400:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:404:+++:Apache/1.3 (Win32):Apache/1\.3\.3[1-3] \(Win32\):Apache/1.3.31-33 (Win32)
+++:HTM:200:200:400:200:200:HTM:HTM:200:400:400:---:405:404:200:404:501:403:+++:Apache/1.3 (Win32)::Apache/1.3.31 (Win32) mod_gzip/1.3.26.1a PHP/5.0.1
#
+++:HTM:200:200:200:500:200:XML:HTM:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
+++:XML:200:200:200:501:200:XML:XML:400:400:400:200:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
HTM:HTM:200:200:200:404:200:HTM:HTM:301:301:400:301:404:404:200:404:404:200:301:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
HTM:HTM:302:200:200:200:200:HTM:HTM:400:400:400:302:302:302:200:302:302:200:302:Apache/2.0 (Unix)::Apache/2.0.49 (Unix) mod_ssl/2.0.49 OpenSSL/0.9.7a DAV/2
HTM:HTM:200:200:200:403:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:403:Apache/2.0 (Unix)::Apache/2.0.59 (FreeBSD) PHP/4.4.4 with Suhosin-Patch mod_ssl/2.0.59 OpenSSL/0.9.8e
HTM:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:405:403:405:501:200:404:::Apache/2.0.59 (Win32) mod_ssl/2.0.59 OpenSSL/0.9.8e PHP/5.2.6
# Apache/2.0.40 (Red Hat Linux) [w/ PHP/4.2.2]
# Apache/2.2.0 (Linux/SUSE)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:302:405:405:200:405:501:200:302:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.0):Apache/2.0.40-2.2.0 (Linux)
XML:XML:200:200:401:401:401:XML:XML:400:400:400:404:405:405:200:405:405:401:401:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
HTM:HTM:200:200:200:501:200:xxx:HTM:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix):Apache/2\.0\.48:Apache/2.0.48 (Linux)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:403:403:200:405:405:302:404:Apache/2.0 (Unix)::Apache/2.0.50 (Fedora) [w/ PHP 4.3.10]
# Apache/2.0.46 (CentOS)
# Apache/2.0.50 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:405:405:302:404:Apache/2.0 (Unix):Apache/2\.0\.[45][0-9]:Apache/2.0.46-2.0.50 (Redhat Linux)
XML:XML:200:200:200:501:200:HTM:XML:400:400:400:404:403:403:200:405:405:302:404:Apache/2.0 (Unix)::Apache/2.0.50 (Fedora)
# Apache/2.0.52 (Red Hat)
# Apache/2.0.53 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:403:405:405:200:405:405:200:404:Apache/2.0 (Unix):Apache/2\.0\.5[23] \((Red Hat|Fedora)\):Apache/2.0.52-2.0.53 (Red Hat)
# Apache/2.0.46 (Red Hat)
# Apache/2.0.52 (CentOS)
# Apache/2.0.55 (Ubuntu) DAV/2 SVN/1.3.1 mod_fastcgi/2.4.2
# Apache/2.2.0 (FreeBSD) mod_ssl/2.2.0 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.2.0 with Suhosin-Patch
###HTM:401:200:401:401:200:401:---:HTM:401:400:400:400:400:404:405:405:200:200:200:200:::Apache/2\.(0\.(4[6-9]|5[0-9])|2\.0) \(Red Hat|CentOS|Ubuntu|FreeBSD|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/2.0.46-2.2.0 (Unix)
+++:xxx:200:200:200:501:200:HTM:xxx:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix):Apache/2\.0\.52 \((Fedora|Red Hat)\):Apache/2.0.52 (Fedora)
HTM:HTM:200:200:403:501:403:XML:HTM:400:400:400:200:405:405:200:405:405:403:404:Apache/2.0 (Unix)::Apache/2.0.51 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:401:401:401:200:401:401:200:404:Apache/2.0 (Unix)::Apache/2.0.52 (CentOS)
+++:XML:200:200:200:501:200:HTM:XML:400:400:400:302:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.53 (Fedora)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:403:405:405:200:404:Apache/2.0 (Unix)::Apache/2.0.53 (Fedora) [w/ PHP/4.3.11]
HTM:HTM:200:200:403:501:403:HTM:HTM:400:400:400:404:403:403:200:405:405:403:404:Apache/2.0 (Unix)::Apache/2.0.54 (Fedora)
+++:XML:200:200:200:501:200:XML:XML:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (Debian GNU/Linux) DAV/2 mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-18 mod_perl/1.999.21 Perl/v5.8.4
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:302:405:501:200:404:Apache/2.0 (Unix)::Apache/2.0.55 (Unix) PHP/4.4.2
HTM:HTM:500:200:403:501:403:HTM:HTM:400:400:400:404:500:500:200:500:500:403:404:Apache/2.0 (Unix)::Apache/2.0.54 (Debian GNU/Linux) mod_jk/1.2.18
XML:XML:404:200:200:200:200:XML:XML:400:400:400:404:404:404:200:404:404:200:403:Apache/2.0 (Unix)::Apache/2.0.59 (FreeBSD) mod_ssl/2.0.59 OpenSSL/0.9.7e-p1 PHP/4.4.7 with Suhosin-Patch mod_fastcgi/2.4.2 proxy_html/2.5
# Apache/2.0.55 (Unix) PHP/4.4.0
# Apache/2.0.59 (Unix)
HTM:HTM:200:200:403:501:403:HTM:HTM:400:400:400:404:405:405:200:405:501:403:404:Apache/2.0 (Unix):Apache/2\.0\.5[5-9] \(Unix\):Apache/2.0.55-2.0.59 (Unix)
# Apache/2.0.50 (Fedora)
# Apache/2.0.51 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:302:302:200:405:405:200:302:Apache/2.0 (Unix):Apache/2\.0\.5[01] \(Fedora\):Apache/2.0.50-2.0.51 (Red Hat)
HTM:HTM:200:200:200:501:200:HTM:xxx:400:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix)::Apache/2.0.46 (Red Hat)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:302:403:403:200:405:405:200:403:Apache/2.0 (Unix)::Apache/2.0.59 (Unix) mod_ssl/2.0.59 OpenSSL/0.9.8f-dev DAV/2 mod_ruby/1.2.6 Ruby/1.8.6(2007-03-13) mod_python/3.3.1 Python/2.5 PHP/5.2.2 mod_perl/2.0.3 Perl/v5.8.8
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/2.2 (Unix)::Apache/2.2.13 (Unix) mod_ssl/2.2.13 OpenSSL/0.9.8e-fips-rhel5 mod_auth_passthrough/2.1 mod_bwlimited/1.4 FrontPage/5.0.2.2635 PHP/5.2.10
HTM:HTM:200:505:505:505:200:HTM:HTM:400:400:400:400:405:405:200:405:405:200:404:Apache/2.2 (Unix)::Apache/2.2.0 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:403:Apache/2.2 (Unix)::Apache/2.2.3 (FreeBSD)
HTM:HTM:400:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:403:Apache/2.2 (Unix)::Apache/2.2.4 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:405:501:200:403:Apache/2.2 (Unix)::Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 PHP/4.4.4 with Suhosin-Patch
HTM:HTM:404:404:404:404:404:HTM:HTM:400:400:400:404:405:405:404:405:501:404:404:Apache/2.2 (Unix)::Apache/2.2.3 (Unix) mod_ssl/2.2.3 OpenSSL/0.9.8a PHP/5.2.0 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.0.49 (Unix) PHP/4.3.6 mod_perl/2.0.2 Perl/v5.8.6
# Apache/2.0.55 (Unix) mod_ssl/2.0.55 OpenSSL/0.9.7e PHP/5.0.5
# Apache/2.2.2 (Unix) mod_ssl/2.2.2 OpenSSL/0.9.7d PHP/4.4.2
# Apache/2.2.3 (Debian) PHP/5.2.0-7 mod_perl/2.0.2 Perl/v5.8.8
+++:xxx:200:200:200:200:200:xxx:xxx:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix):Apache/2\.(0\.(49|5[0-5])|2\.[0-3]) \(Unix|Debian|[A-Za-z /]*Linux[A-Za-z /]*\):Apache/2.0.49-2.2.2 (Unix)
+++:HTM:200:200:200:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:---:+++:Apache/2.0 (Unix)::Apache/2.0.55 (FreeBSD) PHP/4.4.0
+++:HTM:200:403:403:501:200:HTM:HTM:400:400:400:403:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.51 (Fedora)
+++:HTM:403:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:404:+++:Apache/2.0 (Unix)::Apache/2.0.52 (FreeBSD) PHP/4.3.10
# Apache/2.0.51 (Fedora)
# Apache/2.0.52 (Red Hat)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:200:405:405:302:302:Apache/2.0 (Unix):Apache/2\.0\.5[12]:Apache/2.0.51-2.0.52 (Linux)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:405:405:200:405:501:200:404:Apache/2.0 (Unix)::Apache/2.0.59 (Unix) PHP/5.1.6
+++:XML:200:200:200:200:200:XML:XML:400:400:400:200:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (Fedora)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:302:302:302:302:200:404:Apache/2.0 (Unix)::Apache/2.0.55 (Unix) mod_ssl/2.0.55 OpenSSL/0.9.7e PHP/4.4.1
+++:HTM:200:200:200:403:200:XML:HTM:400:400:400:404:403:403:200:403:403:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (Linux/SUSE)
+++:HTM:200:200:200:200:200:HTM:HTM:200:200:400:200:200:200:200:200:200:200:+++:Apache/2.0 (Unix)::Apache/2.0.55 (Unix) PHP/5.1.2
HTM:HTM:200:200:200:200:200:HTM:HTM:400:200:400:200:200:200:200:200:200:200:200:Apache/2.0 (Unix)::Apache/2.0.51 (Fedora)
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:405:200:405:405:302:302:Apache/2.0 (Unix)::Apache/2.0.52 (CentOS)
# Apache/2.0.53 (Debian GNU/Linux)
# Apache/2.0.55 (Debian) PHP/5.1.4-0.1 mod_perl/2.0.2 Perl/v5.8.8
+++:---:200:200:200:501:200:HTM:---:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix):Apache/2\.0\.5[35] \(Debian[A-Za-z /]*\):Apache/2.0.53-55 (Debian GNU/Linux)
# Apache/2.0.54 (Fedora)
# Apache/2.0.54 (Debian GNU/Linux) PHP/4.3.10-18 mod_ssl/2.0.54 OpenSSL/0.9.7e
+++:HTM:404:200:200:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:+++:Apache/2.0 (Unix):Apache/2\.0\.54 \(Fedora|[A-Za-z /]*Linux\):Apache/2.0.54 (Linux)
# Two more precise
# Apache/2.0.55 (Ubuntu) PHP/5.1.6 mod_ssl/2.0.55 OpenSSL/0.9.8b [w/ PHP/5.1.6]
# Apache/2.2.3 (CentOS)
HTM:HTM:404:200:200:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix)::Apache/2\.[02]\.[0-9]+ \((Ubuntu|CentOS)\)
HTM:HTM:404:200:200:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:403:Apache/2.2 (Unix)::Apache/2.2.0 (FreeBSD) mod_ssl/2.2.0 OpenSSL/0.9.7e-p1 PHP/5.1.5
#
HTM:HTM:200:500:500:501:200:HTM:HTM:400:400:400:500:403:403:200:405:501:200:404:Apache/2.0 (Unix)::Apache/2.0.48 (Unix) PHP/4.3.4 FrontPage/5.0.2.2634
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:200:403:403:200:200:200:302:404:Apache/2.0 (Unix)::Apache/2.0.54 (Unix) [w/ PHP/5.1.1]
HTM:HTM:200:503:503:501:200:HTM:HTM:400:400:400:503:405:405:200:405:405:200:404:Apache/2.0 (Unix)::Apache/2.0.54 (Unix) PHP/4.4.7 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_fastcgi/2.4.2 DAV/2 SVN/1.4.2
XML:XML:200:200:200:501:200:XML:XML:400:400:400:200:200:200:200:200:501:200:200:Apache/2.0 (Unix)::Apache/2.0.54 (Linux/SUSE)
# Apache/2.0.55 (Unix) PHP/5.2.1 FrontPage/5.0.2.2635 mod_ssl/2.0.55 OpenSSL/0.9.7e-p1
# Apache/2.0.59 (Unix) PHP/5.2.1 FrontPage/5.0.2.2635 mod_ssl/2.0.59 OpenSSL/0.9.7e-p1
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:405:501:404:404:Apache/2.0 (Unix):Apache/2\.0\.5[5-9]:Apache/2.0.55-2.0.59 (Unix)
XML:XML:200:200:200:200:200:XML:XML:400:400:400:302:405:405:200:405:501:200:404:Apache/2.0 (Unix)::Apache/2.0.55 (Unix) mod_ssl/2.0.55 OpenSSL/0.9.7a PHP/5.1.2
# Apache/2.0.52 (CentOS)
# Apache/2.0.51 (Fedora)
+++:xxx:200:200:200:501:200:HTM:xxx:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.2 (Unix)::Apache/2.2.0 (Unix) PHP/5.1.6
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.58 (Unix)
# Apache/2.2.2 (Fedora)
# Apache/2.2.13 (Linux/SUSE)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.([0-9][^0-9]|1[0-3])):Apache/2.0.40-2.2.13 (Unix)
#
HTM:HTM:200:200:200:501:200:HTM:HTM:400:302:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix)::Apache/2.0.46 (Red Hat)
HTM:HTM:200:200:301:301:301:HTM:HTM:400:400:400:404:405:405:200:405:405:301:301:Apache/2.0 (Unix)::Apache/2.0.46 (Red Hat)
HTM:HTM:200:200:200:500:200:HTM:HTM:400:400:400:404:405:405:200:405:501:302:404:Apache/2.0 (Unix)::Apache/2.0.43 (Unix) mod_ssl/2.0.43 OpenSSL/0.9.6g mod_jk/1.2.0
# Apache/2.0.52 (CentOS)
# Apache/2.0.54 (Fedora)
# Apache/2.0.52 (Scientific Linux)
# Apache/2.2.3 (Scientific Linux)
# Apache/2.2.15 (Scientific Linux)
# Apache/2.4.6 (CentOS)
# Apache/2.4.6 (Red Hat)
# Apache/2.4.6 (Scientific Linux)
# Apache/2.4.10 (Fedora)
# Apache/2.4.17 (Fedora)
HTM:HTM:200:403:403:501:403:HTM:HTM:400:400:400:404:405:405:200:405:405:403:404:Apache/2.0, 2.2, or 2.4:Apache/2\.(0\.5[2-4] \(CentOS|Fedora\)||(0\.52|2\.(3|15)|4\.(6|10|17)) \(Scientific Linux\)):Apache/2.0.52-2.4.17 on CentOS / Oracle Linux / Red Hat / Scientific Linux
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:302:405:405:403:405:405:200:403:Apache/2.0 (Unix)::Apache/2.0.59 (Unix) mod_ssl/2.0.59 OpenSSL/0.9.8f-dev DAV/2 mod_ruby/1.2.6 Ruby/1.8.6(2007-03-13) mod_python/3.3.1 Python/2.5 PHP/5.2.2 mod_perl/2.0.3 Perl/v5.8.8
# Apache/2.0.52 (Red Hat)
# Apache/2.0.53 (Fedora)
# Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/5.2.2 mod_ssl/2.2.3 OpenSSL/0.9.8c
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:405:200:405:405:200:200:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[2-9]|2.[0-3]):Apache/2.0.52-2.2.3 (Linux)
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:403:403:200:405:405:302:302:Apache/2.0 (Unix)::Apache/2.0.52 (BlueQuartz)
+++:HTM:200:200:200:405:200:HTM:HTM:400:400:400:200:405:405:200:405:405:200:+++:Apache/2.0 (Unix)::Apache/2.0.54 (Debian GNU/Linux) DAV/2 mod_python/3.1.3 Python/2.3.5 PHP/4.4.4-0.dotdeb.1 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_perl/1.999.21 Perl/v5.8.4
HTM:HTM:200:503:503:501:200:HTM:HTM:400:400:400:503:VER:VER:200:VER:VER:200:404:Apache/2.0 (Unix)::Apache/2.0.54 (Unix) PHP/4.4.7 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_fastcgi/2.4.2 DAV/2 SVN/1.4.2
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:200:200:200:200:200:200:200:404:Apache/2.0 (Unix)::Apache/2.0.54 (Linux/SUSE) [w/ PHP/4.4.0]
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:405:400:404:Apache/2.0 (Unix)::Apache/2.0.52 (Red Hat)
302:302:200:200:VER:VER:302:302:302:400:400:400:404:405:405:200:405:405:302:302:Apache/2.0 (Unix)::Apache/2.0.55 (Red Hat)
# Apache/2.2.2 (Fedora)
# Apache/2.2.3 (Fedora)
+++:HTM:406:406:406:406:406:HTM:HTM:400:400:400:406:405:405:200:405:405:406:+++:Apache/2.2 (Unix):Apache/2\.2\.[23] \(Fedora\):Apache/2.2.2-3 (Fedora)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:403:400:404:405:405:200:405:501:200:403:Apache/2.2 (Unix)::Apache/2.2.4 (FreeBSD) mod_ssl/2.2.4 OpenSSL/0.9.7e-p1
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:405:200:405:501:302:302:Apache/2.2 (Unix)::Apache/2.2.0 (Unix)
# Apache/2.0.52 (Red Hat)
# Apache/2.0.54 (Fedora)
# Apache/2.2.2 (Fedora)
# Apache/2.2.2 (Fedora) PHP/5.1.4 mod_ssl/2.2.2 OpenSSL/0.9.8a DAV/2
# Apache/2.2.3 (Debian)
# Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.1.5
+++:XML:200:200:200:501:200:HTM:XML:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[0-9]|2\.[0-3]) \(Unix|Red Hat|Fedora|Debian|FreeBSD\):Apache/2.0.52-2.2.3 (Unix)
# More precise
XML:XML:200:200:200:501:200:HTM:XML:400:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Unix)::Apache/2.0.51 (Fedora)
#
+++:HTM:200:200:200:200:200:HTM:HTM:400:400:400:301:301:301:200:301:301:200:+++:Apache/2.2 (Unix)::Apache/2.2.3 (Debian)
+++:XML:200:200:200:405:200:xxx:XML:400:400:400:404:405:405:403:405:501:200:+++:Apache/2.2 (Unix)::Apache/2.2.3 (Debian)
+++:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:404:200:404:405:200:+++:Apache/2.2 (Unix)::Apache/2.2.2 (Fedora) [w/ PHP/5.1.6]
+++:HTM:200:200:200:501:200:XML:---:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.2 (Unix)::Apache/2.2.3 (Mandriva Linux/PREFORK-1mdv2007.0)
+++:---:200:200:200:501:200:XML:---:400:400:400:404:405:405:200:405:501:200:+++:Apache/2.2 (Unix)::Apache/2.2.3 (Unix) PHP/4.4.4 mod_ssl/2.2.3 OpenSSL/0.9.7e-p1
HTM:HTM:404:200:200:501:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/2.2 (Unix)::Apache/2.2.3 (Debian) DAV/2 SVN/1.4.2 PHP/4.4.4-8+etch3 mod_ssl/2.2.3 OpenSSL/0.9.8c mod_apreq2-20051231/2.6.0 mod_perl/2.0.2 Perl/v5.8.8
HTM:HTM:200:200:200:501:200:HTM:HTM:200:200:400:404:405:405:200:405:501:200:200:Apache/2.2 (Unix)::Apache/2.2.4 (Unix) FrontPage/5.0.2.2635 [w/ PHP/4.4.7]
XML:XML:200:200:200:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:404:404:Apache/2.2 (Unix)::Apache/2.2.3 (Debian) PHP/4.4.4-8+etch3 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.0.54 (Fedora)
# Apache/2.2.2 (Unix) DAV/2 PHP/4.4.2 mod_jk/1.2.20
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:405:200:405:405:200:302:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[4-9]|2\.[0-2]):Apache/2.0.54-2.2.2 (Unix)
HTM:HTM:200:200:301:403:301:HTM:HTM:400:400:400:302:403:403:200:403:403:301:302:Apache/2.0 (Unix)::Apache/2.0.52 (CentOS)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:403:405:405:200:405:405:200:403:Apache/2.2 (Unix)::Apache/2.2.4 (Unix) mod_ssl/2.2.4 OpenSSL/0.9.7d DAV/2 PHP/5.2.2 SVN/1.4.3
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:408:Apache/2.2 (Unix)::Apache/2.2.3 (FreeBSD)
HTM:HTM:200:200:403:501:403:HTM:HTM:400:400:400:200:405:405:200:405:501:403:200:Apache/2.2 (Unix)::Apache/2.2.3
HTM:HTM:200:200:404:501:404:HTM:HTM:400:400:400:404:405:405:200:405:501:404:404:Apache/2.2 (Unix)::Apache/2.2.3 (Debian) mod_ssl/2.2.3 OpenSSL/0.9.8c mod_perl/2.0.2 Perl/v5.8.8
#
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:302:405:405:200:405:501:200:+++:Apache/2.0 (Win32)::Apache/2.0.59 (Win32) PHP/4.3.4
HTM:HTM:403:200:404:404:404:HTM:HTM:404:400:400:200:405:405:200:405:501:400:200:Apache/2.0 (Win32)::Apache/2.0.52 (Win32)
# Apache/2.0.54 (Win32) DAV/2 mod_ssl/2.0.54 OpenSSL/0.9.7g PHP/5.0.4 SVN/1.2.3
# Apache/2.2.3 (Win32) DAV/2 mod_ssl/2.2.3 OpenSSL/0.9.8d mod_autoindex_color PHP/5.2.0 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.3 (Win32) DAV/2 mod_ssl/2.2.3 OpenSSL/0.9.8d mod_autoindex_color PHP/5.1.6 mod_perl/2.0.2 Perl/v5.8.8
+++:HTM:403:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):Apache/2\.(0\.5[4-9]|2\.[0-3]) \(Win32\) DAV/2:Apache/2.0.54-2.2.3 (Win32) DAV/2 mod_ssl/2 OpenSSL mod_autoindex_color PHP/5
HTM:HTM:403:200:200:500:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Win32)::Apache/2.0.53 (Win32) mod_ssl/2.0.52 OpenSSL/0.9.7e mod_jk/1.2.8
HTM:HTM:200:200:200:501:200:HTM:HTM:200:400:400:200:405:405:200:405:501:200:200:Apache/2.0 (Win32)::IBM_HTTP_Server/6.0.2.15 Apache/2.0.47 (Win32)
# XAMPP v1.7.3 -- Apache/2.2.14 (Win32) DAV/2 mod_ssl/2.2.14 OpenSSL/0.9.8l mod_autoindex_color PHP/5.3.1 mod_apreq2-20090110/2.7.1 mod_perl/2.0.4 Perl/v5.10.1
---:---:200:200:200:200:200:---:---:200:400:400:404:405:405:200:405:405:200:404:Apache 2.2 (Win32):Apache/2\.2\.14 \(Win32\) DAV/2:Apache/2.2 (Win32) DAV/2 mod_ssl/2.2 OpenSSL/0.9.8 mod_autoindex_color PHP/5.3
# Apache/2.0.55 (Win32) mod_ssl/2.0.55 OpenSSL/0.9.8a PHP/4.4.1
# Apache/2.2.2 (Win32) [w/ PHP/5.1.4]
# Apache/2.2.4 (Win32) PHP/4.4.4
+++:---:403:200:200:200:200:---:---:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):Apache/2\.(0\.5[5-9]|2\.[0-4]) \(Win32\) .*PHP/[45]:Apache/2.0.55-2.2.4 (Win32) w/ PHP/4 or PHP/5
---:---:403:200:200:200:200:---:---:200:400:400:404:405:405:200:405:501:200:404:::Apache/2.0.54 (Win32) PHP/5.0.4
# Apache/2.0.47 (Win32) mod_ssl/2.0.47 OpenSSL/0.9.7b DAV/2
# Apache/2.0.48 (Win32) mod_ssl/2.0.48 OpenSSL/0.9.7c PHP/4.3.5 DAV/2
# Apache/2.0.50 (Win32) PHP/4.3.11 DAV/2
# Apache/2.0.54 (Win32) SVN/1.4.2 DAV/2 PHP/5.1.4 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.0.55 (Win32) DAV/2 PHP/5.1.0 mod_python/3.2.8 Python/2.4.2 SVN/1.3.0
+++:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Win32):Apache/2\.0\.(4[7-9]|5[0-5]) \(Win32\):Apache/2.0.47-55 (Win32)
+++:---:200:200:200:200:200:---:---:400:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Win32):Apache/2\.0\.5[12] \(Fedora|CentOS|[A-Za-z /]*Linux\):Apache/2.0.51-52 (Linux)
# Apache/2.2.3 (CentOS)
# Apache/2.2.0 (Fedora)
---:---:200:200:200:200:200:---:---:400:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Unix):Apache/2\.2\.[0-3] \(CentOS|Fedora\):Apache/2.2.0-2.2.3 (Red Hat Linux)
# Conflicting => raw signature
---:---:200:302:302:302:302:---:---:400:400:400:404:405:405:200:405:405:302:404:Apache/2.0 (Unix)::Apache/2.0.52
+++:---:403:200:200:501:200:HTM:---:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32)::Apache/2.0.59 (Win32)
+++:XML:403:200:200:200:200:XML:XML:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Unix)::Apache/2.0.55 (Win32) PHP/5.1.2
# More precise & conflicting
# Apache/2.0.55 (Win32) PHP/4.3.10
# Apache/2.2.6 (Win32) PHP/5.2.5
XML:XML:403:200:200:200:200:XML:XML:200:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Win32) or Apache/2.2 (Win32):^Apache/2\.[02]\.[0-9]+ \(Win32\):Apache/2.0-2.2 (Win32) w/ PHP
# Apache/2.0.54 (Win32) DAV/2 PHP/4.3.11
# Apache/2.0.54 (Win32) DAV/2 SVN/1.2.3 mod_fastcgi/2.4.2
# Apache/2.0.55 (Win32) PHP/5.1.0 SVN/1.4.2 DAV/2
+++:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:+++:Apache/2.0 (Win32):Apache/2\.0\.5[45] \(Win32\) .*DAV/2:Apache/2.0.54-55 (Win32) DAV/2
# More precise:
# Apache/2.2.0 (Win32) DAV/2 mod_ssl/2.2.0 OpenSSL/0.9.8a mod_autoindex_color PHP/5.1.1
# Apache/2.2.2 (Win32) DAV/2 mod_ssl/2.2.2 OpenSSL/0.9.8b mod_autoindex_color PHP/5.1.4
# Apache/2.2.6 (Win32) DAV/2 mod_ssl/2.2.6 OpenSSL/0.9.8e mod_autoindex_color PHP/5.2.4
HTM:HTM:403:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32):^Apache/2\.2\.[0-6] \(Win32\) DAV/2 mod_ssl/2\.2\.[0-6] OpenSSL/0\.9\.8[a-e] mod_autoindex_color PHP/5\.[12]\.[14]:Apache/2.2.0-2.2.6 (Win32) DAV/2 mod_ssl/2.2 OpenSSL/0.9.8 mod_autoindex_color PHP/5
HTM:HTM:403:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Win32)::Apache/2.0.45 (Win32) PHP/4.3.1
HTM:HTM:403:200:200:501:200:XML:HTM:200:302:400:302:405:405:200:405:501:200:302:Apache/2.0 (Win32)::Apache/2.0.48 (Win32) mod_perl/1.99_10 Perl/v5.8.0 mod_ssl/2.0.48 OpenSSL/0.9.7c PHP/4.3.4
# Apache/2.2.4 (Win32) DAV/2 SVN/1.4.4
# Apache/2.0.54 (Win32) mod_jk/1.2.14 SVN/0.35.1 DAV/2
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Win32) or Apache/2.2 (Win32):Apache/2\.(0\.5[4-9]|2\.[0-4]) \(Win32\) .*DAV/2:Apache/2.0.54-2.2.4 (Win32) DAV/2
HTM:HTM:403:200:200:200:200:HTM:HTM:200:400:400:302:405:405:200:405:501:200:302:Apache/2.2 (Win32)::Apache/2.2.3 (Win32) mod_ssl/2.2.3 OpenSSL/0.9.8c mod_jk/1.2.18
# Apache/2.2.8 (Win32) DAV/2 mod_ssl/2.2.8 OpenSSL/0.9.8g mod_autoindex_color PHP/5.2.5
# Apache/2.2.9 (Win32) DAV/2 mod_ssl/2.2.9 OpenSSL/0.9.8i mod_autoindex_color PHP/5.2.6
# Apache/2.2.10 (Win32) SVN/1.6.6 DAV/2
# Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
# Apache/2.2.14 (Win32) SVN/1.6.6 DAV/2 mod_ssl/2.2.14 OpenSSL/0.9.8l mod_autoindex_color PHP/5.3.1 mod_apreq2-20090110/2.7.1 mod_perl/2.0.4 Perl/v5.10.1
HTM:HTM:200:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32):^Apache/2\.2\.([89]|1[0-4]) \(Win32\) (SVN/1[0-9.]+ )?DAV/2:Apache/2.2.8-2.2.11 (Win32) DAV/2
HTM:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32)::Apache/2.2.9 (Win32) SVN/1.5.2 DAV/2
HTM:HTM:200:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Win32)::Apache/2.2.9 (Win32)
# Apache/2.2.8 (Win32) DAV/2 mod_ssl/2.2.8 OpenSSL/0.9.8g mod_autoindex_color PHP/5.2.5
# Apache/2.2.9 (Win32) DAV/2 mod_ssl/2.2.9 OpenSSL/0.9.8i mod_autoindex_color PHP/5.2.6
# Apache/2.2.11 (Win32) DAV/2 mod_ssl/2.2.11 OpenSSL/0.9.8i PHP/5.2.9
# Apache/2.2.12 (Win32) DAV/2 mod_ssl/2.2.12 OpenSSL/0.9.8k mod_autoindex_color PHP/5.3.0 mod_perl/2.0.4 Perl/v5.10.0
HTM:HTM:200:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32):^Apache/2\.2\.([89]|1[0-2]) \(Win32\) DAV/2 mod_ssl/2\.2\.([89]|1[0-2]) OpenSSL/0.9.8[g-k] (mod_autoindex_color )?PHP/5\.(2\.[5-9]|3\.0):Apache/2.2.8-2.2.11 (Win32) DAV/2 mod_ssl/2.2.8-2.2.11 OpenSSL/0.9.8g-0.9.8i PHP/5.2.5-5.2.9
# Apache/2.0.48 (Win32)
# Apache/2.2.3 (Win32)
+++:XML:403:200:200:501:200:HTM:XML:200:400:400:404:405:405:200:405:501:200:+++:Apache/2.0 (Win32) or Apache/2.2 (Win32):^Apache/2\.(0\.(4[89]|5[0-9])|2\.[0-3]):Apache/2.0.48-2.2.3 (Win32)
# Apache/2.2.11 (Win32) PHP/5.3.0
# Apache/2.2.11 (Win32) PHP/5.2.9-2
# WAMP (32 BITS & PHP 5.3) 2.2E, Apache/2.2.22 (Win32) PHP/5.3.13
XML:XML:200:200:200:200:200:XML:XML:200:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Win32):^Apache/2\.2\.(11|2[12]) \(Win32\):Apache/2.2.11-2.2.22 (Win32) PHP/5
# WAMP (32 BITS & PHP 5.3) 2.2D, Apache/2.2.21 (Win32) PHP/5.3.10
# WAMP (32 BITS & PHP 5.4) 2.2E, Apache/2.2.22 (Win32) PHP/5.4.3
HTM:HTM:200:403:403:403:403:HTM:HTM:403:400:400:403:403:403:200:403:403:403:403:Apache/2.2 (Win32):^Apache/2\.2\.2[12] \(Win32\):Apache/2.2.21 (Win32) PHP/5.3 or Apache/2.2.22 (Win32) PHP/5.4
#
400:400:501:200:200:200:400:400:400:400:501:200:404:501:501:501:501:501:404:400:::aProtect
+++:200:400:200:200:200:404:404:404:404:400:200:404:400:400:400:400:400:+++:+++:ArGoSoft/1.8::ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1.8 (1.8.4.7)
# Conflicting
# ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1.8 (1.8.9.3)
# ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1.8 (1.8.9.5)
200:200:400:200:200:200:404:404:404:404:400:200:404:400:400:400:400:400:404:404:ArGoSoft/1.8:ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1\.8 \(1\.8\.9\.[3-5]\):ArGoSoft Mail Server Pro for WinNT/2000/XP, Version 1.8 (1.8.9.3-1.8.9.5)
#
---:---:403:503:---:---:---:---:---:---:403:503:---:403:403:---:---:---:400:503:BearShare::BearShare Pro 5.2.4.1
# Cougar 4.1.0.3860
# Cougar 4.1.0.3930
400:400:400:500:500:500:500:400:500:500:400:500:400:400:400:400:400:400:500:500:::Cougar 4.1.0
400:400:200:200:400:505:400:400:456:200:501:400:200:501:501:501:501:501:200:200:::Cougar/9.01.01.3862
+++:---:200:200:200:200:---:---:---:---:---:200:404:404:404:---:---:---:---:+++:::CommuniGatePro/4.1.8
---:---:---:---:---:200:---:---:---:---:---:200:404:404:404:---:---:404:404:---:::CommuniGatePro/5.2.16 _trial_
401:401:501:401:401:501:501:501:501:401:501:401:---:501:501:501:501:501:404:404:DLink:^$:DLink DI-714P+ DSL router
200:404:501:200:200:200:200:200:200:200:200:200:404:501:501:501:501:501:200:---:DLink:Micro-Web:Micro-Web [DLink DI-714P+ DSL router]
200:---:500:200:200:200:---:---:---:500:500:200:500:500:500:500:500:500:500:500:^$::DVRWebServer
HTM:xxx:501:HTM:HTM:501:501:501:501:404:400:200:400:501:501:501:501:501:400:HTM:::Embedded HTTP Server. [Linksys RVL200 SSL VPN]
HTM:HTM:400:400:400:200:400:400:400:400:400:400:404:405:405:405:501:501:200:404:jetty/6::Jetty(6.1.5)
HTM:HTM:400:400:400:200:400:400:400:400:400:400:404:405:405:403:501:501:200:404:jetty/6::Jetty(6.1.6)
HTM:HTM:404:400:400:200:400:400:400:400:400:400:404:405:405:403:501:501:404:404:::Jetty(6.1.16)
HTM:HTM:400:400:400:200:400:400:400:400:400:400:200:200:200:200:200:200:200:200:::Jetty(6.1.x)
HTM:HTM:400:400:400:200:400:400:400:400:400:400:404:405:405:403:501:501:404:404:^$::Jetty [bundled w/ OpenFire]
HTM:HTM:200:400:400:200:400:400:400:400:400:400:404:405:405:405:501:501:404:404:::Jetty(7.x.y-SNAPSHOT)
# Jetty 7.6.10.v20130312
HTM:HTM:404:400:400:200:400:400:400:500:400:400:404:404:404:404:404:404:400:404:::Jetty 7.6
#
200:200:501:200:200:200:501:501:501:403:403:200:501:501:501:501:501:501:400:400:::GeoHttpServer
+++:401:400:401:401:400:401:400:400:302:500:401:---:400:400:400:400:400:401:+++:::GoAhead-Webs
HTM:HTM:406:406:400:501:200:HTM:HTM:400:400:400:406:406:406:200:406:406:200:404:::GWS/1.0
200:200:501:505:505:501:200:---:---:400:501:200:HTM:501:501:501:501:501:400:---::^$:Handlink WG-601 wireless PnP subscriber gateway
#
200:200:400:VER:VER:400:200:400:200:400:400:400:403:501:501:501:501:501:400:404:thttpd+haproxy:^thttpd:thttpd/2.25nb thru haproxy
200:200:200:200:200:400:200:400:200:400:400:400:404:405:405:405:405:501:200:404:apache+haproxy:^Apache:Apache/2.2 thru haproxy
#
HTM:HTM:HTM:200:200:HTM:HTM:HTM:HTM:404:HTM:200:404:HTM:HTM:HTM:HTM:HTM:HTM:HTM:::LANCOM 821+ (Annex B) 6.32.0021 / 28.03.2007
---:---:---:200:200:200:---:---:---:200:---:200:404:404:404:404:404:404:200:404:::LANDesk Management Agent/1.0
400:400:200:400:400:501:400:400:400:200:404:400:411:200:200:501:200:501:200:500:::lighttpd/1.4.10
400:400:200:505:400:501:400:400:400:302:302:400:411:200:200:501:200:501:302:302:::lighttpd/1.4.13 [w/ PHP/5.2.0-8+etch4]
400:400:200:505:400:501:400:400:400:200:404:400:411:200:200:501:200:501:200:200:::lighttpd/1.4.15
400:400:200:505:400:501:400:400:400:404:404:400:411:404:404:501:404:501:404:404:::lighttpd/1.4.15 [w/ PHP/5.2.3]
# Samsung Galaxy S2 - UPnP?
400:400:400:400:400:400:400:400:400:400:VER:400:400:400:400:400:400:400:400:400:::Linux/2.6.35.7-I9100XWKJ2-CL676699 DoaHTTP
200:200:501:200:400:501:200:---:---:403:403:200:400:501:501:501:501:501:400:200:::Linux/2.4.19-rmk4, UPnP/1.0, Intel SDK for UPnP devices /1.2
# Archos 70
200:200:501:200:400:501:200:---:---:---:---:---:400:501:501:501:501:501:400:200:::Linux/2.6.29-omap1, UPnP/1.0, Portable SDK for UPnP devices/1.6.6
# Raw signature
404:400:400:404:404:404:404:400:400:400:400:404:404:501:501:501:501:501:404:404:::LINUX/2.4 UPnP/1.0 BRCM400/1.0
HTM:HTM:404:VER:VER:HTM:200:HTM:HTM:404:404:200:404:HTM:HTM:404:HTM:HTM:200:404:::Mbedthis-AppWeb/2.0.4
HTM:HTM:404:VER:VER:HTM:200:HTM:HTM:200:301:200:404:400:404:HTM:HTM:HTM:200:404:Mbedthis-AppWeb/2:^Mbedthis-App[wW]eb/2\.[24]\.[20]:Mbedthis-AppWeb/2.2.2-2.4.0
HTM:HTM:404:VER:VER:HTM:200:HTM:HTM:404:404:200:400:400:404:404:HTM:HTM:200:404:::Mbedthis-AppWeb/2.1.0 [might be Psiphon/1.6]
# Embedthis Appweb 4.0.0 on Windows (Embedthis-http/4.0.0)
406:406:---:406:406:200:---:---:---:---:---:200:404:405:405:406:405:405:200:404:::Embedthis-http/4.0.0
+++:---:501:401:401:401:---:---:---:400:501:401:---:501:501:501:501:501:400:+++:::micro_httpd
400:HTM:503:200:400:503:200:400:400:400:400:200:501:501:503:503:503:503:404:404:mikrotik:^$:mikrotik routeros 4.10
#
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:501:501:404:404:::Microsoft-IIS/4.0
404:404:200:200:404:404:400:400:400:400:400:404:405:403:403:200:501:501:404:404:::Microsoft-IIS/4.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:404:404:::Microsoft-IIS/5.0
XML:XML:200:200:XML:400:400:400:400:400:400:400:405:403:403:404:400:411:404:404:::Microsoft-IIS/5.0
HTM:HTM:403:200:200:200:200:HTM:HTM:400:400:400:411:411:403:403:400:411:200:414:::Microsoft-IIS/5.0 [thru proxy cache]
HTM:HTM:400:400:400:400:400:400:400:400:400:400:405:403:403:200:400:400:200:414:::Microsoft-IIS/5.0
200:200:404:200:200:400:400:400:400:400:400:400:405:404:404:200:404:404:200:414:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:404:404:200:404:404:200:414:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:404:404:404:404:404:404:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:404:400:411:200:414:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:302:302:302:302:302:302:200:302:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:403:403:200:414:::Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:400:405:200:200:200:200:200:200:200:::Microsoft-IIS/5.0
404:404:200:200:404:400:400:400:400:400:400:404:405:411:404:200:400:411:404:404:::Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:302:405:403:403:200:404:411:200:414:::Microsoft-IIS/5.0
HTM:HTM:400:HTM:HTM:HTM:404:400:400:400:400:200:405:403:403:200:400:411:200:414:::Microsoft-IIS/5.0
302:302:200:200:302:400:400:400:400:400:400:400:405:403:403:200:400:411:302:414:::Microsoft-IIS/5.0
500:500:200:200:500:400:400:400:400:400:400:400:405:403:403:200:400:411:500:414:::Microsoft-IIS/5.0
403:403:200:200:403:400:400:400:400:400:400:400:405:403:403:200:400:411:403:500:::Microsoft-IIS/5.0 [w/ ASP.NET]
401:401:404:401:401:400:400:400:400:400:400:400:405:403:403:404:400:411:401:414:::Microsoft-IIS/5.0 [w/ ASP.NET]
#
200:200:404:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:200:400:::Microsoft-IIS/6.0 [w/ ASP.NET]
302:302:400:505:400:400:302:400:400:400:400:400:411:411:405:501:405:405:302:400:::Microsoft-IIS/6.0 [w/ ASP.NET 2.0.50727]
302:302:200:505:400:400:302:400:400:400:400:400:411:411:501:501:501:501:302:400:::Microsoft-IIS/6.0
500:500:200:505:400:400:500:400:400:400:400:400:411:411:501:501:501:501:500:400:::Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:401:400:400:400:400:400:411:411:501:501:501:501:401:400:::Microsoft-IIS/6.0
200:200:503:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0 [w/ ASP.NET 2.0.50727]
HTM:HTM:200:505:400:400:400:400:400:400:400:400:411:411:501:501:501:501:400:400:::Microsoft-IIS/6.0
HTM:HTM:500:505:400:400:200:400:400:400:400:400:411:411:500:501:500:500:200:400:::Microsoft-IIS/6.0
HTM:HTM:400:400:400:400:200:400:400:400:400:400:411:400:400:400:400:400:200:400:::Microsoft-IIS/6.0
HTM:HTM:401:505:400:400:400:400:400:400:400:400:411:411:401:501:401:401:400:400:::Microsoft-IIS/6.0
# Microsoft-HTTPAPI/2.0
# Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:200:200:200:200:200:400::^(Microsoft-IIS/6\.0|Microsoft-HTTPAPI/2\.0)$:Microsoft-IIS/6.0 or Microsoft-HTTPAPI/2.0
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:411:200:400:::Microsoft-IIS/6.0
400:400:500:200:400:400:200:400:400:500:500:200:411:411:403:200:400:411:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:200:501:200:200:200:400:::Microsoft-IIS/6.0
400:400:500:200:400:400:403:400:400:500:500:403:411:411:501:200:501:501:403:403:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:404:501:400:411:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:501:404:404:501:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:200:200:200:200:200:400:::Microsoft-IIS/6.0
200:200:404:505:400:400:200:400:400:400:400:400:411:411:404:404:404:404:404:400:::Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:400:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:404:404:404:404:404:400:::Microsoft-IIS/6.0
400:400:500:200:400:400:200:400:400:500:500:200:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0
HTM:HTM:404:505:400:400:200:400:400:400:400:400:411:411:404:404:404:404:404:400:::Microsoft-IIS/6.0
200:200:400:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:400:200:400:::Microsoft-IIS/6.0
XML:XML:200:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:403:400:400:400:400:400:411:411:501:501:501:501:403:400:::Microsoft-IIS/6.0 [w/ ASP.NET 2.0.50727]
HTM:HTM:200:505:400:400:400:400:400:400:400:400:411:411:403:501:403:403:400:400:::Microsoft-IIS/6.0
# Raw banner
+++:HTM:401:505:400:400:401:400:400:400:400:400:411:411:401:401:401:401:401:+++:::Microsoft-IIS/6.0
#
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:200:400:::Microsoft-IIS/7.0
HTM:HTM:404:505:400:400:200:400:400:400:400:400:411:411:404:404:404:404:200:400:::Microsoft-IIS/7.5
---:---:400:505:400:400:200:400:400:400:400:400:411:411:404:501:404:404:200:400:::Microsoft-IIS/7.5 [w/ ASP.NET]
HTM:HTM:500:505:400:400:200:400:400:400:400:400:411:411:405:501:405:405:200:400:::Microsoft-IIS/7.5 [w/ ASP.NET and PHP/5.3.24]
xxx:xxx:404:505:400:400:200:400:400:400:400:400:411:411:404:404:404:404:200:400:::Microsoft-IIS/7.5 [w/ ASP.NET 4.0.30319]
HTM:HTM:500:505:400:400:404:400:400:400:400:400:411:411:405:501:405:405:404:400:::Microsoft-IIS/8.0
#
200:404:404:200:200:404:---:---:---:404:404:200:404:404:404:404:404:404:404:404:::Nanox WebServer
200:200:---:200:200:200:501:501:501:200:200:200:xxx:xxx:xxx:xxx:xxx:xxx:---:---:::NetDecision-HTTP-Server/1.0
#
400:HTM:200:400:400:400:400:400:400:404:404:400:401:401:401:200:401:400:404:404:Netscape/3::Netscape-Enterprise/3.6 SP1
400:HTM:404:200:400:400:400:400:400:200:404:200:500:403:403:200:403:403:414:414:Netscape/5::NetWare-Enterprise-Web-Server/5.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:501:413:501:501:200:403:Netscape/6::Netscape-Enterprise/6.0
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:404:200:404:404:200:404:::nginx/0.3.43
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:404:200:404:501:403:403:::nginx/0.3.47 [?]
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:405:200:405:501:302:302:::nginx/0.4.13 [w/ PHP/5.1.6]
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:404:405:404:501:200:404:::nginx/0.5.20 [?]
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:404:200:404:501:302:403:::nginx/0.5.7 [w/ PHP/4.4.0]
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:200:411:405:405:405:501:200:200:::nginx/0.7.65
HTM:HTM:502:200:404:501:404:HTM:HTM:400:400:400:405:405:405:403:501:501:404:404:Resin/2::Resin/2.1.17
HTM:HTM:HTM:200:400:200:200:HTM:HTM:HTM:HTM:400:---:501:501:501:501:501:200:400:::Resin/3.0.17
200:200:405:200:200:405:405:405:405:200:200:400:400:400:405:405:405:405:400:400:::RomPager/4.07 UPnP/1.0
200:200:405:200:200:405:405:405:405:404:404:200:400:400:405:405:405:405:400:400:::RomPager/4.07 UPnP/1.0
400:400:405:200:200:405:405:405:405:200:200:400:400:400:405:405:405:405:400:400:::RomPager/4.51 UPnP/1.0
400:400:404:200:200:404:404:404:404:404:404:400:404:404:404:404:404:404:400:400:::RomPager/4.51 UPnP/1.0
401:401:501:401:400:501:401:---:---:401:401:401:401:501:501:501:501:501:401:401:::TVersity/1.0
400:HTM:501:VER:VER:VER:200:400:400:400:400:400:200:501:501:501:501:501:200:200:::thttpd/2.20c 21nov01
HTM:HTM:HTM:VER:VER:VER:404:HTM:HTM:HTM:HTM:400:404:HTM:HTM:HTM:HTM:HTM:404:404:::thttpd/2.21 20apr2001
505:505:405:401:401:405:401:401:401:401:405:401:405:405:405:405:405:405:401:505::^$:Thomson CWMP 7.4.2.7
400:400:400:200:400:400:400:400:400:400:400:200:400:404:404:404:404:404:404:404::^$:Unison Play UniFS
# This must be a CCTV
HTM:HTM:401:VER:VER:VER:HTM:HTM:HTM:401:401:401:401:401:401:401:401:401:401:401:::uniVIS [Unique Vision Controle Center]
401:401:401:401:401:401:---:---:---:401:401:401:401:401:401:401:401:401:401:401:::WatchGuard Firewall
401:401:401:401:401:401:401:401:401:---:401:401:401:401:401:401:401:401:401:401:::WatchGuard Firewall
HTM:HTM:501:VER:VER:VER:200:400:400:400:400:200:200:501:501:501:501:501:400:200:::Waveplus HTTPD
+++:400:401:401:401:401:400:400:400:401:401:401:501:501:501:501:501:501:413:+++:::WindWeb/2.0
+++:400:401:401:401:401:400:400:400:401:401:401:501:501:501:501:501:501:302:+++:::WindWeb/2.0
+++:HTM:400:200:400:400:400:400:400:404:404:200:200:400:400:400:400:400:200:+++:::WYM/1.0
+++:HTM:400:200:400:400:400:400:400:404:404:200:404:400:400:400:400:400:200:+++:::WYM/1.0
---:---:404:200:---:---:---:---:---:404:404:200:404:404:404:404:404:404:404:404:::XLink Kai Engine/7.4.18
200:200:404:VER:VER:200:---:---:---:404:404:200:404:404:404:404:404:404:404:404::^$:XWebPlay
HTM:HTM:400:400:400:---:200:400:400:400:400:400:405:403:403:405:405:501:200:404:::Zeus/4.2
HTM:HTM:400:400:400:---:200:400:400:400:400:400:405:405:501:501:501:501:200:404:::Zeus/4.3
HTM:HTM:400:400:400:---:200:400:400:400:400:400:405:405:405:405:405:501:200:404:::Zeus/4.3
HTM:HTM:400:400:400:501:200:400:400:400:400:400:405:400:501:501:501:501:200:404:::Zeus/4_3
XML:XML:400:400:400:---:200:400:400:400:400:400:405:403:403:501:501:501:200:404:::Zeus/4.3
400:500:404:VER:400:400:400:400:400:404:404:200:404:403:404:404:404:404:200:404:::Zope/(unreleased version, python 2.3.3, win32) ZServer/1.1 Plone/2.0.5
HTM:HTM:200:200:200:200:200:xxx:HTM:404:200:400:404:500:401:404:404:200:200:404:::Zope/(Zope 2.8.8-final, python 2.3.4, linux2) ZServer/1.1 Plone/Unknown
HTM:HTM:200:200:200:200:200:HTM:HTM:200:404:400:200:409:404:404:404:404:200:200:::Zope/(unreleased version, python 2.3.3, linux2) ZServer/1.1 Plone/2.0.3
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:302:401:404:404:200:200:404:::Zope/(Zope 2.8.4-final, python 2.3.5, linux2) ZServer/1.1 Plone/Unknown
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:401:401:404:404:200:200:404:::Zope/(Zope 2.9.7-final, python 2.4.4, linux2) ZServer/1.1 Plone/2.5.3-final
+++:200:501:501:200:200:200:200:200:200:200:200:200:501:501:501:501:501:501:+++:::ZOT-828/2.01
#################################
#### More precise signatures ####
#################################
# RomPager/4.07 UPnP/1.0
# Allegro-Software-RomPager/4.06
400:400:405:200:200:405:405:405:405:404:404:400:400:400:405:405:405:405:400:400::^(Allegro-Software-)?RomPager/4\.0[67]:Allegro-Software-Rompager/4.06-4.07
400:200:405:200:200:405:405:405:405:404:404:400:400:400:405:405:405:405:400:400:::RomPager/4.07 UPnP/1.0
HTM:HTM:400:200:200:501:HTM:HTM:HTM:400:400:400:501:501:501:501:501:501:200:404:Apache/1.1::Apache/1.1.1
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:200:404:Apache/1.3 (Unix)::Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:404:200:501:501:302:302:Apache/1.3 (Unix)::Apache/1.3.3 Cobalt (Unix)  (Red Hat/Linux)
# Apache/1.3.12 (Unix)  (SuSE/Linux) mod_fastcgi/2.2.2 balanced_by_mod_backhand/1.0.8 DAV/1.0.0 mod_perl/1.24 PHP/3.0.16
# Apache/1.3.19 (Unix)  (SuSE/Linux) mod_throttle/3.0 mod_layout/1.0 mod_fastcgi/2.2.2 balanced_by_mod_backhand/1.1.0 mod_perl/1.24
# Apache/1.3.22 (Unix)  (Red-Hat/Linux) mod_python/2.7.6 Python/1.5.2 mod_ssl/2.8.5 OpenSSL/0.9.6b DAV/1.0.2 PHP/4.0.6 mod_perl/1.24_01 mod_throttle/3.1.2
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_python/2.7.6 Python/1.5.2 mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 mod_throttle/3.1.2
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.(1[2-9]|2[0-3]):Apache/1.3.12-1.3.23 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.12 (Unix) PHP/4.1.2 FrontPage/4.0.4.3
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.4 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.3.4 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.6 (Unix) mod_perl/1.21 mod_ssl/2.2.8 OpenSSL/0.9.2b
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:302:Apache/1.3 (Unix):Apache/1\.3\.([6-9]|1[0-9]|20):Apache/1.3.6-1.3.20 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:VER:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_fastcgi/FSDATA-1.0 mod_jk/1.1.0 mod_throttle/3.2.0 Embperl/2.0b8 mod_perl/1.29 PHP/4.4.3 mod_ssl/2.8.28 OpenSSL/0.9.8b
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:404:::Apache/1.3.33 (Debian GNU/Linux) mod_gzip/1.3.26.1a PHP/4.4.0-0.dotdeb.0 mod_ssl/2.8.22 OpenSSL/0.9.7e mod_perl/1.29 DAV/1.0.3
# Apache/1.3.37 Ben-SSL/1.57 (Unix)
# Apache/1.3.29 (Unix) PHP/4.4.1 mod_ssl/2.8.16 OpenSSL/0.9.6k
XML:XML:200:200:400:501:200:HTM:XML:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-7]):Apache/1.3/29-37 (Unix)
# Apache/1.3.26 (Unix)
# Apache/1.3.26 (Unix) PHP/4.2.4-dev
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
HTM:HTM:200:403:400:501:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Unix)::Apache/1.3.27 (Unix) mod_gzip/1.3.19.1a PHP/4.3.1
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) PHP/5.2.0
# Apache/1.3.26 (Unix) PHP/4.3.9 mod_ssl/2.8.9 OpenSSL/0.9.7a
# Apache/1.3.26 (Unix) Debian GNU/Linux FrontPage/5.0.2.263
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:200:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:404:403:403:200:404:501:302:302:Apache/1.3 (Unix)::Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.1.2 mod_auth_pam_external/0.1 FrontPage/4.0.4.3 mod_perl/1.25
# Apache/1.3.29 (Unix)
# Apache/1.3.31 (Unix) mod_ssl/2.8.17 OpenSSL/0.9.7d
# Apache/1.3.37 (Unix) PHP/5.2.2 with Suhosin-Patch
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:200:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-7]) \(Unix\):Apache/1.3.29-1.3.37 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:403:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_jk/1.2.10 mod_ssl/2.8.22 OpenSSL/0.9.7g
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:406:403:403:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_fastcgi/2.4.2 mod_gzip/1.3.26.1a mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/5.2.0 mod_ssl/2.8.28 OpenSSL/0.9.7e-p1
HTM:HTM:200:200:400:501:200:HTM:HTM:404:301:400:404:405:404:200:404:501:200:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) FrontPage/5.0.2.2635 mod_ssl/2.8.28 OpenSSL/0.9.7l
XML:XML:200:200:400:403:200:HTM:XML:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7j PHP/4.4.1
# Apache/1.3.27 (Unix) PHP/4.3.2
# Apache/1.3.31 (Unix) mod_python/2.7.10 Python/2.2.2 mod_webapp/1.2.0-dev mod_perl/1.29 mod_throttle/3.1.2 PHP/4.3.10 FrontPage/5.0.2.2510 mod_ssl/2.8.18 OpenSSL/0.9.7d
# Apache/1.3.33 (Darwin) PHP/4.3.6
# Apache/1.3.36 (Unix) PHP/4.4.2
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 mod_ssl/2.8.28 OpenSSL/0.9.8b
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-1.3.37 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:404:Apache/1.3 (Unix)::Apache/1.3.27-33 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:VER:VER:VER:200:VER:VER:200:VER:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) FrontPage/5.0.2.2510 mod_ssl/2.8.16 OpenSSL/0.9.7a [w/ PHP/4.3.10]
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:403:Apache/1.3 (Unix)::Apache/1.3.34 (Unix) PHP/4.4.2 rus/PL30.22
# Apache/1.3.27 (Unix) mod_perl/1.27 PHP/4.2.3 mod_ssl/2.8.12 OpenSSL/0.9.7-beta3
# Apache/1.3.27 (Unix) PHP/4.1.2 mod_ssl/2.8.11 OpenSSL/0.9.6g
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6 DAV/1.0.2 PHP/4.1.2 mod_perl/1.24_01
# Apache/1.3.33
# Apache/1.3.34 (Unix) PHP/4.4.1
# Apache/1.3.37 (Unix) PHP/5.2.2-dev
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 mod_ssl/2.8.28 OpenSSL/0.9.8b
# Apache/1.3.37 (Unix) mod_auth_pgsql/0.9.12 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7e-p1 PHP-CGI/0.1b [w/ PHP/4.3.10]
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.6 mod_ssl/2.8.28 OpenSSL/0.9.7e-p1
# Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7d PHP/4.4.1
# Apache/1.3.33 (Unix) PHP/4.3.10 FrontPage/5.0.2.2623
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-1.3.37 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:401:401:200:401:405:403:403:Apache/1.3 (Unix)::Apache/1.3.27 (Darwin) DAV/1.0.3
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-21 mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.4.6-0.dotdeb.2 with Suhosin-Patch mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.37 (Unix) mod_fastcgi/2.4.2 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
# Apache/1.3.34 Ben-SSL/1.55 (Debian) PHP/4.4.4-8+etch3
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6m DAV/1.0.2 PHP/4.1.2 mod_perl/1.26
# Apache/1.3.34 (Unix) FrontPage/5.0.2.2510 mod_perl/1.29 mod_ssl/2.8.25 OpenSSL/0.9.7g PHP-CGI/0.1b
# Apache/1.3.31 (Unix) PHP/4.3.8
# Apache-AdvancedExtranetServer/1.3.33 (Mandrakelinux/4mdk.i1) FrontPage/5.0.2.2635 mod_throttle/3.1.2 mod_ssl/2.8.22 OpenSSL/0.9.7d PHP/4.3.10
# Oracle-Application-Server-10g/9.0.4.0.0 Oracle-HTTP-Server
# Apache/1.3.34 (Ubuntu)
# Apache/1.3.41 (Unix) mod_log_bytes/1.2 mod_bwlimited/1.4 mod_auth_passthrough/1.8 FrontPage/5.0.2.2635 mod_ssl/2.8.31 OpenSSL/0.9.7a
# Apache/1.3.28 (SolutionIP) mod_perl/1.28 mod_ssl/2.8.15 OpenSSL/0.9.7b
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):Oracle-Application-Server-10g/9|(Apache(-AdvancedExtranetServer)?/1\.3\.(2[7-9]|3[0-9]|4[01])(.*\((Ubuntu|Unix|Debian|.*[lL]inux.*|SolutionIP)\).*)?$):Apache/1.3.27-1.3.41 (Unix)
# basic httpd on OpenBSD 4.0 - 4.3
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7j
# Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7g
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:501:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) mod_ssl/2.8.16 OpenSSL/0.9.7
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:404:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) Debian GNU/Linux PHP/4.1.2 mod_perl/1.26
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) DAV/1.0.3 PHP/4.3.4 mod_perl/1.29 mod_ssl/2.8.16 OpenSSL/0.9.7c
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 AuthMySQL/3.2
# Apache/1.3.33 (Unix) ModVMAX/1.0 mod_fastcgi/2.4.2 mod_ssl/2.8.22 OpenSSL/0.9.7a PHP/4.4.0
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-16
# Apache/1.3.34 (Unix) AuthMySQL/2.20 PHP/4.4.1
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a PHP-CGI/0.1b
# Apache/1.3.37 (Unix) mod_deflate/1.0.21 mod_jk/1.2.5 mod_fastcgi/2.4.2 PHP/5.1.6 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.4 FrontPage/5.0.2.2634a mod_ssl/2.8.28 OpenSSL/0.9.7a
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-1.3.37 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:404:403:404:405:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Darwin) mod_jk/1.2.6 DAV/1.0.3 mod_ssl/2.8.24 OpenSSL/0.9.7l PHP/4.4.4
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:302:Apache/1.3 (Unix)::Apache/1.3.34 (Unix) DAV/1.0.3
#
HTM:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:::Apache/1.3.23 (Win32)
HTM:HTM:200:200:400:400:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32)::Apache/1.3.26 (Win32) PHP/4.2.1
# Apache/1.3.27 (Win32)
# Apache/1.3.31 (Win32) PHP/4.2.3
# Apache/1.3.33 (Win32) PHP/4.3.11
# Apache/1.3.34 (Win32) PHP/4.4.1
HTM:HTM:200:200:400:200:200:HTM:HTM:200:400:400:404:405:404:200:404:501:403:404:Apache/1.3 (Win32):Apache/1\.3\.(2[7-9]|3[0-4]) \(Win32\):Apache/1.3.27-1.3.34 (Win32)
#
XML:XML:200:200:200:501:200:HTM:XML:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:403:403:200:405:405:200:404:Apache/2.0 (Unix)::Apache/2.0.40 (Red Hat Linux)
XML:XML:200:200:200:200:200:XML:XML:400:400:400:200:200:200:200:200:200:200:404:Apache/2.0 (Unix)::Apache/2.0.49 (Linux/SuSE)
# Apache/2.0.44 (Unix)
# Apache/2.0.52 (Unix) DAV/2 mod_ssl/2.0.52 OpenSSL/0.9.7d mod_jk/1.2.18
# Apache/2.2.4 (FreeBSD) mod_ssl/2.2.4 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.2.3 with Suhosin-Patch mod_python/3.3.1 Python/2.4.4 SVN/1.4.3 mod_perl/2.0.3 Perl/v5.8.8
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:403:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.[0-4]):Apache/2.0.40-2.2.4 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:403:Apache/2.0 (Unix)::Apache/2.0.49 (Unix) PHP/4.3.6 mod_ssl/2.0.49 OpenSSL/0.9.7c-p1
# Apache/2.0.46 (Red Hat)
# Apache/2.0.50 (Fedora)
# Apache/2.0.51 (Fedora)
# Apache/2.0.54 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:302:404:Apache/2 (Unix):Apache/2\.0\.(4[6-9]|5[0-4]):Apache/2.0.46-2.0.54 (Red Hat)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:405:200:405:501:200:404:Apache/2 (Unix)::Apache/2.0.54
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:302:405:405:200:405:405:200:302:Apache/2.0 (Unix)::Apache/2.0.54 (Unix) mod_perl/1.99_09 Perl/v5.8.0 mod_ssl/2.0.54 OpenSSL/0.9.7l DAV/2 FrontPage/5.0.2.2635 PHP/4.4.0 mod_gzip/2.0.26.1a
# Apache/2.0.54 (Unix) PHP/5.0.4
# Apache/2.0.59 (FreeBSD)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:403:Apache/2.0 (Unix):Apache/2\.0\.5[4-9]:Apache/2.0.54-2.0.59 (Unix)
# Apache/2.0.55 (FreeBSD) DAV/2 PHP/4.4.0
# Apache/2.0.59
# Apache/2.2.3 (FreeBSD) mod_ssl/2.2.3 OpenSSL/0.9.7e-p1 DAV/2 PHP/5.1.6 with Suhosin-Patch
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:403:Apache/2 (Unix):Apache/2\.(0\.5[5-9]|2\.(1\.[0-9]+|2\.[0-3])):Apache/2.0.55-2.2.3 (Unix)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:302:Apache/2.0 (Unix)::Apache/2.0.59 (FreeBSD) PHP/5.1.5
# Apache/2.0.46 (Red Hat)
# Apache/2.0.53 (Unix) DAV/2 PHP/4.3.10
# Apache/2.0.51 (Fedora)
# Apache/2.0.46 (CentOS)
# Apache/2.2.2 (Fedora)
# Apache/2.2.3 (Debian) DAV/2 PHP/5.2.0-8+etch4 mod_ssl/2.2.3 OpenSSL/0.9.8c
# Apache/2.2.4 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.[0-4]):Apache/2.0.46-2.2.4 (Linux)
# Apache/2.0.49 (Unix) PHP/4.4.0
# Apache/2.0.52 (Red Hat)
# Apache/2.0.54 (Fedora)
# Apache/2.0.59 (Unix) mod_ssl/2.0.59 OpenSSL/0.9.7g DAV/2 PHP/4.4.4
# Apache/2.2.3 (Debian) PHP/4.4.4-8+etch1 mod_ssl/2.2.3 OpenSSL/0.9.8c
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:200:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.(49|5[0-9])|2\.[0-3]):Apache/2.0.49-2.2.3 (Linux)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:404:Apache/2.0 (Unix)::Apache/2.0.52 (Red Hat)
HTM:HTM:200:200:404:403:404:HTM:HTM:400:400:400:404:403:403:200:403:403:404:404:Apache/2.0 (Unix)::Apache/2.0.59 (Unix) mod_ssl/2.0.59 OpenSSL/0.9.7j DAV/2 PHP/5.1.6
# Apache/2.0.54 (Unix) PHP/5.2.0
# Apache/2.2.9 (Ubuntu) mod_fastcgi/2.4.6 PHP/5.2.6-2ubuntu4 with Suhosin-Patch mod_ssl/2.2.9 OpenSSL/0.9.8g
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:403:405:501:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[4-9]|2\.[0-9]) \([A-Z][a-z]+\):Apache/2.0.54-2.2.9 (Unix)
# Apache/2.0.44 (Unix) PHP/4.3.4
# Apache/2.0.48 (Linux/SuSE)
# Apache/2.0.49 (Linux/SuSE)
# Apache/2.0.49 (Unix) PHP/4.3.2
# Apache/2.0.53 (Unix) PHP/5.0.4
# Apache-AdvancedExtranetServer/2.0.53 (Mandriva Linux/PREFORK-9.4.102mdk) mod_ssl/2.0.53 OpenSSL/0.9.7e PHP/4.3.10
# Apache/2.2.4 (Unix) mod_ssl/2.2.4 OpenSSL/0.9.7d PHP/5.2.2
# Apache/2.2.9 (Ubuntu) mod_jk/1.2.26 mod_mono/1.9 Phusion_Passenger/2.0.6 PHP/5.2.6-2ubuntu4.1 with Suhosin-Patch mod_python/3.3.1 Python/2.5.2
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache(-AdvancedExtranetServer)?/2\.(0\.(4[4-9]|5[0-9])|2\.[0-9]):Apache/2.0.44-2.2.9 (Unix)
# Apache/2.0.40 (Red Hat Linux) mod_perl/1.99_07-dev Perl/v5.8.0 PHP/4.2.2 mod_ssl/2.0.40 OpenSSL/0.9.7a
# Apache/2.0.44
# Apache/2.0.46 (Red Hat)
# Apache-AdvancedExtranetServer/2.0.48 (Mandrake Linux/6mdk) mod_ssl/2.0.48 OpenSSL/0.9.7c PHP/4.3.4
# Apache/2.0.58 (Unix) mod_ssl/2.0.58 OpenSSL/0.9.7i
# Apache/2.2.3 (Debian) mod_ssl/2.2.3 OpenSSL/0.9.8c PHP/4.4.4-8+etch3 mod_perl/2.0.2 Perl/v5.8.8
# Apache/2.2.4 (Unix) mod_ssl/2.2.4 OpenSSL/0.9.8e mod_jk/1.2.19
# Apache/2.2.6 (Gentoo) mod_ssl/2.2.6 OpenSSL/0.9.8e
# Apache/2.2.8 (Gentoo) mod_ssl/2.2.8 OpenSSL/0.9.8g
# Apache/2.2.9 (Gentoo) mod_ssl/2.2.9 OpenSSL/0.9.8g
# Apache/2.2.11 (Ubuntu) PHP/5.2.10-5hardy~ppa2 with Suhosin-Patch
# Apache/2.2.17 (Unix) mod_ssl/2.2.17 OpenSSL/1.0.0d Axis2C/1.6.0
# Apache/2.2.15 (CentOS)
# Apache/2.2.29 (Unix)
# Apache/2.4.3 (Unix)
# Apache/2.4.6 (Unix)
# Apache/2.4.16 (Unix) found on Ubuntu 16.04.1 LTS
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix) or Apache/2.4 (Unix):Apache(-AdvancedExtranetServer)?/2\.(0\.[45][0-9]|2\.([0-9]|1[0157]|29)|4\.([36]|16))( .*)?$:Apache/2.0.40-2.0.59, 2.2.0-2.2.10, 2.2.11, 2.2.17, 2.2.29, 2.4.3, 2.4.6, 2.4.16 (Unix) or Apache/2.2.15 (CentOS)
# Apache 2.2.9-r1 w/ PHP 5.2.6-r6 on Gentoo 2008.0 - kernel 2.6.25-hardened-r5 :
# Apache/2.2.9 (Gentoo) PHP/5.2.6
# Apache 2.2.21-r1 w/ PHP 5.3.8 on kernel 3.0.6-gentoo :
# Apache/2.2.21 (Gentoo) mod_ssl/2.2.21 OpenSSL/1.0.0e
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:405:405:501:200:404:Apache/2.2 (Unix):^Apache/2\.2\.(9|1[0-9]|2[01]) \(Gentoo\):Apache/2.2.9-2.2.21 (Gentoo) PHP/5.2.6-5.3.8
# Apache/2.0.54 (Unix)
# Apache/2.2.3 (Unix) PHP/4.4.6
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:405:200:405:501:200:200:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[4-9]|2\.[0-3]):Apache/2.0.54-2.2.3 (Unix)
XML:XML:200:200:200:200:200:XML:XML:400:400:400:404:405:405:200:405:501:200:403:Apache/2.2 (Unix)::Apache/2.2.2 (Unix) PHP/5.1.4
# Apache/2.2.3 (CentOS)
# Apache/2.2.4 (Unix) DAV/2
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:403:405:405:200:404:Apache/2.2 (Unix):^Apache/2\.2\.[34] \(Unix|CentOS\):Apache/2.2.3-2.2.4 (Unix)
XML:XML:200:200:200:200:200:XML:XML:400:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Unix)::Apache/2.2.3 (Debian) PHP/4.4.4-8+etch3 mod_ssl/2.2.3 OpenSSL/0.9.8c
HTM:HTM:200:200:200:501:200:HTM:HTM:200:200:400:404:405:405:200:501:501:200:404:Apache/2.2 (Unix)::Apache/2.2.2 (Unix) PHP/4.4.2 mod_jk/1.2.15
HTM:HTM:404:200:404:404:404:HTM:HTM:404:404:400:404:404:404:200:404:404:404:404:Apache/2.2 (Unix)::Apache/2.2.4 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:404:301:400:404:405:405:200:405:501:200:404:Apache/2.2 (Unix)::Apache/2.2.3 (Unix) PHP/4.4.4
HTM:HTM:200:200:200:405:200:HTM:HTM:400:400:400:405:405:405:200:405:405:200:403:::Apache/2.3.15-dev (Unix) mod_ssl/2.3.15-dev OpenSSL/1.0.0c
#
HTM:HTM:200:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:403:404:Apache/2.0 (Win32)::Apache/2.0.39 (Win32) PHP/4.2.2
HTM:HTM:403:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:501:200:302:Apache/2.0 (Win32)::Apache/2.0.55 (Win32) JRun/4.0
# Apache/2.2.3 (Win32) PHP/5.2.13
# Apache/2.2.3 (Win32) PHP/5.2.0RC6-dev
XML:XML:403:200:200:501:200:HTM:XML:200:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Win32)::Apache/2.2.3 (Win32) PHP/5.2
XML:XML:403:200:200:200:200:XML:XML:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32)::Apache/2.2.0 (Win32) DAV/2 mod_ssl/2.2.0 OpenSSL/0.9.8a mod_autoindex_color proxy_html/2.5 PHP/5.1.1
# Raw signature
HTM:HTM:200:401:401:401:401:HTM:HTM:401:400:400:401:401:401:200:401:401:401:401:Apache/2.2 (Win32)::Apache/2.2.8 (Win32)
#
xxx:xxx:405:505:400:200:200:400:400:400:400:400:411:501:501:404:404:404:404:400:::cisco-IOS
400:400:200:505:400:501:400:400:400:404:200:400:411:404:404:501:404:501:200:500:lighttpd/1.4::lighttpd/1.4.13
400:400:200:505:505:505:404:400:400:400:400:400:411:404:404:501:404:501:404:404:lighttpd/1.5::lighttpd/1.5.0
# Lotus-Domino/5.0.8
# Lotus-Domino/5.0.9
HTM:HTM:405:200:200:200:200:HTM:HTM:200:500:400:500:405:405:405:501:501:500:500:Lotus-Domino/5.0:^Lotus-Domino/5\.0\.[89]:Lotus-Domino/5.0.8-5.0.9
400:400:200:401:400:401:401:400:400:401:401:400:401:405:405:200:405:501:401:400:Lotus-Domino/6.5:^Lotus-Domino$:Lotus-Domino/R6.5.5
#
200:200:400:200:200:200:400:400:400:200:200:200:400:400:400:400:400:400:400:---:::McAfee-Agent-HttpSvr/1.0
#
HTM:HTM:404:200:HTM:501:200:400:400:200:404:200:501:501:501:501:501:501:200:500:::Microsoft-IIS/3.0
200:200:200:200:200:400:400:400:400:400:400:400:405:403:403:200:501:501:200:404:::Microsoft-IIS/4.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:501:501:200:404:::Microsoft-IIS/4.0
HTM:HTM:404:200:HTM:404:400:400:400:400:400:400:405:404:404:404:404:404:200:404:::Microsoft-IIS/4.0
200:200:200:200:200:400:400:400:400:400:400:400:405:403:403:200:501:501:200:200:::Microsoft-IIS/4.0
HTM:HTM:404:200:HTM:---:400:400:400:400:400:400:405:404:404:404:404:404:404:404:::Microsoft-IIS/5.0
200:200:400:200:200:400:400:400:400:400:400:400:302:302:302:200:302:302:200:400:::Microsoft-IIS/5.0 [w/ ASP.NET 1.1.4322]
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:411:404:200:400:411:200:500:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:400:411:200:500:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:404:400:411:404:404:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:200:414:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:403:403:200:400:411:200:414:::Microsoft-IIS/5.0
404:404:200:200:404:400:400:400:400:400:400:404:405:403:403:200:400:411:404:404:::Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:400:405:501:501:200:501:501:200:414:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:501:501:200:501:501:200:414:::Microsoft-IIS/5.0
200:200:404:200:200:400:400:400:400:400:400:400:405:404:404:404:404:404:200:414:::Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:400:405:403:403:404:400:411:404:404:::Microsoft-IIS/5.0
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:200:200:200:200:200:200:414:::Microsoft-IIS/5.0
HTM:HTM:404:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:200:414:::Microsoft-IIS/5.0
404:404:404:200:404:400:400:400:400:400:400:404:405:404:404:404:404:404:404:404:::Microsoft-IIS/5.0
HTM:HTM:404:200:HTM:400:400:400:400:400:400:400:405:404:404:404:404:404:404:404:::Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:400:301:400:400:200:400:400:200:301:::Microsoft-IIS/5.0
# Microsoft-IIS/5.0
# Microsoft-IIS/5.1
HTM:HTM:200:200:HTM:400:400:400:400:400:400:400:405:411:404:200:400:411:200:414:Microsoft-IIS/5.0 or Microsoft-IIS/5.1:^Microsoft-IIS/5\.[01]:Microsoft-IIS/5.0-5.1
#
500:500:400:505:400:400:500:400:400:400:400:400:411:411:404:501:404:404:500:400:::Microsoft-IIS/6.0 [w/ ASP.NET 1.1.4322]
200:200:200:505:400:400:200:400:400:400:400:400:411:411:403:501:400:411:200:400:::Microsoft-IIS/6.0
500:500:200:505:400:400:500:400:400:400:400:400:411:411:403:501:400:411:500:400:::Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0
200:200:200:505:400:400:200:400:400:400:400:400:411:411:501:501:501:501:200:400:::Microsoft-IIS/6.0
HTM:HTM:200:505:400:400:200:400:400:400:400:400:411:411:404:501:400:411:200:400:::Microsoft-IIS/6.0
400:400:500:200:400:400:200:400:400:500:500:200:411:411:501:200:501:501:200:400:::Microsoft-IIS/6.0
500:500:200:505:400:400:200:400:400:400:400:200:411:411:501:501:501:501:500:400:::Microsoft-IIS/6.0 [w/ PHP/5.2.3]
HTM:HTM:200:505:400:400:400:400:400:400:400:400:411:411:403:501:400:400:400:400:::Microsoft-IIS/6.0
#
400:400:400:400:400:400:200:400:400:200:200:200:200:400:400:400:400:400:200:200:::MiniServ/0.01
400:HTM:200:200:400:400:200:400:200:404:404:200:500:500:500:200:500:500:404:403:Netscape/3::Netscape-Enterprise/3.6 SP3
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:200:200:200:200:501:501:200:200:Netscape/4::Netscape-Enterprise/4.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:404:404:200:501:501:200:404:Netscape/4::Netscape-Enterprise/4.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:405:501:501:200:403:::Sun-ONE-Web-Server/6.1
# Netscape-Enterprise/6.0
# Sun-ONE-Web-Server/6.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:404:401:401:200:501:501:200:403:Netscape/6:^(Netscape-Enterprise/6.0|Sun-ONE-Web-Server/6.1):Netscape-Enterprise/6.0 or Sun-ONE-Web-Server/6.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:401:401:200:501:501:200:403:Netscape/4::Netscape-Enterprise/4.1
---:HTM:200:505:HTM:501:200:HTM:HTM:HTM:HTM:400:405:405:405:200:501:501:200:403:Netscape/4::Netscape-Enterprise/4.1
#
500:500:500:VER:VER:400:500:500:500:500:500:400:404:404:404:404:404:404:401:500:sap-web-appl-srv:^$:SAP Web Application Server [R3S]
400:400:400:400:400:400:400:400:400:400:400:400:200:200:200:200:200:200:200:200:::SAP Web Application Server (1.0;700) or SAP NetWeaver Application Server / ABAP 700
400:400:200:VER:VER:VER:400:400:400:200:200:200:200:200:200:200:200:200:200:200:sap-bw-srv:^$:SAP BW [unconfigured host]
#
401:401:400:401:401:401:401:400:400:401:400:401:401:400:400:400:400:400:400:400:::Speed Touch WebServer/1.0
# Oracle9iAS/9.0.2 Oracle HTTP Server
# Apache/1.3.9 (Unix)  (Red Hat/Linux) mod_jk/1.2.2
# Apache/1.3.12 (Unix)  (Red Hat/Linux) mod_ssl/2.6.6 OpenSSL/0.9.5a mod_perl/1.24
# Apache/1.3.20 Sun Cobalt (Unix) mod_ssl/2.8.4 OpenSSL/0.9.6 PHP/4.3.10 FrontPage/5.0.2.2510 mod_perl/1.26
# Apache/1.3.23 (Unix) PHP/4.1.0
# Apache/1.3.23 (Unix) PHP/4.0.6 FrontPage/4.0.4.3
# Apache/1.3.23 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.7 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):(Apache/1.3\.(9|1[0-9]|2[0-3]))|Oracle9iAS/9:Apache/1.3.9-1.3.23 (Unix) or Oracle9iAS/9.0.2 Oracle HTTP Server
200:200:501:VER:VER:501:400:400:400:404:501:200:404:501:501:501:501:501:404:404:::OwnServer1.0 [eyeMax DVR]
# Resin/2.1.10	# Resin/2.1.16
HTM:HTM:HTM:200:HTM:200:200:---:---:HTM:HTM:400:404:501:501:501:501:501:200:400:Resin/2:Resin/2\.1\.1[0-6]:Resin/2.1.10-2.1.16
200:200:405:200:200:405:405:405:405:404:404:400:400:400:405:405:405:405:400:400:::RomPager/4.07 UPnP/1.0
501:501:xxx:404:404:xxx:xxx:xxx:xxx:501:xxx:404:xxx:xxx:xxx:xxx:xxx:xxx:404:404::^$:Skype [not a real web server]
200:200:---:200:200:---:200:200:200:200:---:200:200:---:---:---:---:---:200:---:::SQ-WEBCAM [AV-TECH AVC787 Digital Video Recorder]
# WDaemon/6.0.8
# WDaemon/9.0.7
200:400:501:200:200:200:400:400:400:404:404:200:404:501:501:501:501:501:404:404:WDaemon:WDaemon/[6-9]\.[0-9]:WDaemon/6.0.8 to 9.0.7
400:400:501:200:200:200:400:400:400:404:404:400:404:501:501:501:501:501:404:404:WDaemon::WDaemon/10.0.0
400:400:200:200:200:200:400:400:400:200:200:200:501:501:501:501:501:501:413:413:::WindWeb/2.0
HTM:HTM:400:400:400:501:200:400:400:400:400:400:405:405:405:405:405:501:200:404:Zeus/4::Zeus/4.2
HTM:HTM:302:400:400:200:400:400:400:400:400:400:404:405:405:403:501:501:404:404::^$:Zimbra Collaboration Suite
# BigIP filtering proxy
302:302:302:302:302:302:---:---:---:302:302:302:302:302:302:302:302:302:302:302::RAW:BigIP
302:302:301:301:302:302:---:---:---:302:302:302:301:301:301:301:301:301:302:302::RAW:BigIP
##############################
### Conflicting signatures ###
##############################
# Apache/1.3.0 Ben-SSL/1.18 (Unix) FrontPage/3.0.4.2
# Apache/1.3.1.1 SSL/1.15 PHP/4.0b2
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:501:501:403:403:Apache/1.3 (Unix):^Apache/1\.3\.[01](\..*| .*|)$:Apache/1.3.0-1.3.1 (Unix)
# Apache/1.2.6 FrontPage/3.0.4
# Apache/1.3.1.1 SSL/1.15 PHP/4.0b2
# Unix: unsure?!
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:501:501:403:403:Apache/1.2 (Unix) or Apache/1.3 (Unix):Apache/1\.(2\.[6-9]|3[01]):Apache/1.2.6-1.3.1 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:403:Apache/1.3 (Unix)::Apache/1.3.12 (Unix)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix)::Apache/1.3.14 (Unix) mod_jk PHP/4.0.2
# Apache/1.3.6 (Unix)
# Apache/1.3.9 (Unix)
# Apache/1.3.12 (Unix) PHP/3.0.16 PHP/4.3.9
# Apache/1.3.12 (Unix) mod_perl/1.24 ApacheJserv/1.1.2
# Apache/1.3.19 Ben-SSL/1.44 (Unix)
# Apache/1.3.22 (Unix) PHP/4.0.6 rus/PL30.9
# Apache/1.3.24 (Unix) PHP/4.1.2
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.([6-9]|1[0-9]|2[0-4]) .*\(Unix\):Apache/1.3.6-1.3.24 (Unix)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:403:Apache/1.3 (Unix)::Apache/1.3.22 (Unix)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.20 (Linux/SuSE) mod_jk mod_ssl/2.8.4 OpenSSL/0.9.6b PHP/4.0.6 mod_perl/1.26 mod_fastcgi/2.2.2
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:302:302:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/5.2.2 mod_ssl/2.8.28 OpenSSL/0.9.7f
# Apache/1.3.29 (Unix) FrontPage/5.0.2.2635 DAV/1.0.3 PHP/4.3.10 mod_gzip/1.3.19.1a mod_fastcgi/2.2.12 mod_ssl/2.8.16 OpenSSL/0.9.7a
# Apache/1.3.29 (Unix) PHP/4.3.4
# Apache/1.3.31 (Unix) FrontPage/5.0.2.2635 PHP/4.4.7 with Suhosin-Patch
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.(29|3[01]):Apache/1.3.29-1.3.31 (Unix)
# Apache/1.3.26 (Unix) PHP/4.3.3
# Apache/1.3.26 (Unix) mod_gzip/1.3.26.1a FrontPage/5.0.2.2623 mod_ssl/2.8.9 OpenSSL/0.9.6a
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.26 (Unix)
# Apache/1.3.26 (Unix) PHP/4.2.2
# Apache/1.3.26 (Unix) PHP/4.3.9
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:404:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) PHP/4
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:302:404:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_jk/1.2.0 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
xxx:xxx:200:200:400:200:200:xxx:xxx:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.28 (Linux/SuSE) PHP/4.3.3 [X-Accelerated-By: PHPA/1.3.3r2]
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-19 mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.33 (ALT Linux/alt1.M24.3) mod_ssl/2.8.24 OpenSSL/0.9.7d PHP/4.3.10-ALT
HTM:HTM:403:200:400:200:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.33:Apache/1.3.33 (Linux)
# Apache/1.3.34 (Unix) PHP/4.4.2
# Apache/1.3.37
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.3[4-7]:Apache/1.3.34-1.3.37 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:403:Apache/1.3 (Unix)::Apache/1.3.34 MicroRack (Unix) PHP/4.4.4 mod_ssl/2.8.25 OpenSSL/0.9.8a
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:403:403:Apache/1.3 (Unix)::Apache/1.3.36 (Unix) PHP/4.4.2
HTM:HTM:200:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:403:403:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7e-p1 PHP/4.4.6 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix) PHP/4.4.4 mod_throttle/3.1.2 FrontPage/5.0.2.2635 mod_psoft_traffic/0.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) PHP/4.1.2 mod_perl/1.26
# Apache/1.3.33 (Debian GNU/Linux) mod_fastcgi/2.4.2 PHP/4.3.10-18
# Apache/1.3.37 (Unix) mod_gzip/1.3.26.1a mod_throttle/3.1.2
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:302:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[3-7]):Apache/1.3.27-1.3.37 (Unix)
XML:XML:200:200:400:200:200:XML:XML:400:400:400:404:405:404:501:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.29 (Unix) PHP/5.1.4 mod_jk/1.2.15 mod_ssl/2.8.16 OpenSSL/0.9.7j
# Apache/1.3.27 (Unix) PHP/4.3.2 mod_ssl/2.8.14 OpenSSL/0.9.7b
# Apache/1.3.37 (Unix) PHP/4.4.7 with Suhosin-Patch mod_ssl/2.8.28 OpenSSL/0.9.7e-p1
HTM:HTM:200:403:400:501:403:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-7]) \(Unix\) PHP/4:Apache/1.3.27-1.3.37 (Unix) PHP/4
# Apache/1.3.37 Ben-SSL/1.57 (Unix) FrontPage/5.0.2.2635 PHP/4.1.2
# Apache/1.3.37 Ben-SSL/1.57 (Unix) PHP/4.4.1 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.37 Ben-SSL/1.57 (Unix)
HTM:HTM:404:200:400:200:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4.3.8 rus/PL30.20
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:403:501:200:404:Apache/1.3 (Unix)::Apache/1.3.28 (Linux/SuSE) mod_jk/1.2.3-dev mod_ssl/2.8.15 OpenSSL/0.9.7b
HTM:HTM:404:200:400:501:200:HTM:HTM:400:400:400:404:404:404:200:404:404:200:404:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_ssl/2.8.22 OpenSSL/0.9.7d VDB/1.1.1-se
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) PHP/4.3.0
# Apache/1.3.28 (Unix)
# Apache/1.3.33 (Unix)
# Apache/1.3.37 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:302:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[0-7]):Apache/1.3.27-1.3.37 (Unix)
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:403:403:403:200:403:403:200:403:Apache/1.3 (Unix)::Apache/1.3.28 (Unix) PHP/4.3.4
# Apache/1.3.31 (Unix) PHP/4.3.0
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-16
HTM:HTM:200:200:400:302:302:HTM:HTM:400:400:400:404:405:404:200:404:501:302:404:Apache/1.3 (Unix):Apache/1\.3\.3[1-3] .* PHP/4\.3:Apache/1.3.31-1.3.33 (Unix) PHP/4.3
HTM:HTM:400:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) mod_perl/1.27
# Apache/1.3.22 (Unix)  (Red-Hat/Linux)
# Apache/1.3.26 (Linux/SuSE) mod_ssl/2.8.10 OpenSSL/0.9.6g mod_jk/1.2.0
# Apache/1.3.26 (Unix) Debian GNU/Linux mod_gzip/1.3.19.1a mod_auth_pgsql/0.9.12 ApacheJServ/1.1.2 mod_ssl/2.8.9 OpenSSL/0.9.6c
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:405:404:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.2[2-6] :Apache/1.3.22-1.3.26 (Unix)
HTM:HTM:200:200:400:301:301:HTM:HTM:400:400:400:404:405:404:200:404:501:301:301:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) mod_gzip/1.3.26.1a mod_python/2.7.10 Python/2.3.5 PHP/4.3.10-21
HTM:HTM:200:200:400:301:301:HTM:HTM:400:400:400:404:405:404:200:404:501:301:403:Apache/1.3 (Unix)::Apache/1.3.33 (Unix) PHP/4.4.1
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:302:405:302:200:302:501:200:200:Apache/1.3 (Unix)::Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-19
HTM:HTM:403:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:403:403:Apache/1.3 (Unix)::Apache/1.3.34 (Unix) PHP/4.4.1 mod_ssl/2.8.25 OpenSSL/0.9.7e
HTM:HTM:200:200:400:400:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:404:Apache/1.3 (Unix)::Apache/1.3.26 (Unix) PHP/3.0.18 FrontPage/4.0.2.6920
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_fastcgi/2.2.12 mod_jk/1.2.0 mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_perl/1.26 PHP/4.3.3 FrontPage/5.0.2 mod_ssl/2.8.12 OpenSSL/0.9.6b
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:200:404:501:302:404:Apache/1.3 (Unix)::Apache/1.3.27 (Unix)  (Red-Hat/Linux)
# Apache/1.3.33 (Darwin)
# Apache/1.3.34 (Unix) FrontPage/5.0.2.2623
# Apache/1.3.41 (Darwin
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:405:404:403:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.(3[3-9]|4[01]):Apache/1.3.33-1.3.41 (Unix)
# Apache/1.3.33 (Unix) PHP/4.3.10 mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.34 (Unix) PHP/4.3.7
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:403:Apache/1.3 (Unix):Apache/1\.3\.3[34] \(Unix\):Apache/1.3.33-1.3.34 (Unix)
HTM:HTM:200:200:400:200:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:404::Apache/1.3 (Unix)::Apache/1.3.34 (Unix) PHP/5.0.5 mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 FrontPage/5.0.2.2635 mod_ssl/2.8.25 OpenSSL/0.9.7f
# Apache/1.3.29 (Unix) PHP/4.3.6 mod_perl/1.29
# Apache/1.3.36 (Unix) mod_perl/1.29 PHP/4.3.11 mod_ssl/2.8.27 OpenSSL/0.9.7d
# Apache/1.3.33 (Debian GNU/Linux) PHP/4.3.10-19 mod_perl/1.29
# Apache/1.3.37 (Unix) PHP/4.4.6 mod_deflate/1.0.21 mod_ssl/2.8.28 OpenSSL/0.9.8c
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:200:405:200:200:200:501:200:200:Apache/1.3 (Unix):Apache/1\.3\.(29|3[0-7]):Apache/1.3.29-1.3.37 (Unix)
# Apache/1.3.27 (Unix)  (Red-Hat/Linux) mod_python/2.7.8 Python/1.5.2 mod_ssl/2.8.12 OpenSSL/0.9.6b DAV/1.0.3 PHP/4.1.2 mod_perl/1.26 mod_throttle/3.1.2
# Apache/1.3.33 (Debian GNU/Linux) Sun-ONE-ASP/4.0.0 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7e
# Apache/1.3.37 (Unix) mod_auth_passthrough/1.8 mod_log_bytes/1.2 mod_bwlimited/1.4 PHP/4.4.6 FrontPage/5.0.2.2635.SR1.2 mod_ssl/2.8.28 OpenSSL/0.9.7a
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:200:404:Apache/1.3 (Unix):Apache/1\.3\.(2[7-9]|3[3-7]):Apache/1.3.27-1.3.37 (Unix)
# Apache/1.3.33 (Unix) PHP/5.0.4 FrontPage/5.0.2.2635 mod_ssl/2.8.22 OpenSSL/0.9.7d
# Apache/1.3.37 Ben-SSL/1.57 (Unix) PHP/4.3.10 FrontPage/5.0.2.2510
HTM:HTM:200:200:400:501:200:HTM:HTM:400:400:400:404:403:403:200:404:501:403:403:Apache/1.3 (Unix):Apache/1\.3\.3[3-7]:Apache/1.3.33-1.3.37 (Unix)
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7a PHP/4.4.4 mod_perl/1.29 FrontPage/5.0.2.2510
# Apache/1.3.37 (Unix) mod_ssl/2.8.28 OpenSSL/0.9.7e PHP/4.3.11
HTM:HTM:200:200:400:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/1.3 (Unix)::Apache/1.3.37 (Unix)
#
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.52 (Red Hat)
# Apache/2.0.54 (Unix) DAV/2 PHP/5.1.1
# Apache/2.0.55 (Unix) mod_perl/1.99_17-dev Perl/v5.8.5 mod_ssl/2.0.55 OpenSSL/0.9.7a PHP/4.3.11 FrontPage/5.0.2.2634
# Apache/2.2.11 (Unix) mod_ssl/2.2.11 OpenSSL/0.9.8b DAV/2 PHP/5.2.8
HTM:HTM:200:200:200:403:200:HTM:HTM:400:400:400:404:403:403:200:403:403:200:404:Apache/2 (Unix):Apache/2\.(0\.[4][0-9]|2\.([0-9]( |$)|1[01])):Apache/2.0.40-2.2.11 (Unix)
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:403:Apache/2.0 (Unix)::Apache/2.0.48 [PHP/4.3.4]
# Apache/2.0.43 (Unix) mod_ssl/2.0.43 OpenSSL/0.9.7a mod_jk/1.2.1
# Apache/2.0.52 (FreeBSD) PHP/4.3.9
# Apache/2.0.52 (FreeBSD) PHP/4.3.9 mod_ssl/2.0.52 OpenSSL/0.9.7d
# Apache/2.0.54 (FreeBSD) PHP/5.2.0 with Suhosin-Patch mod_ssl/2.0.54 OpenSSL/0.9.7d
# Apache/2.0.55 (Unix) PHP/5.0.5 mod_ssl/2.0.55 OpenSSL/0.9.7g
# Apache/2.2.3 (Unix) PHP/4.4.3
# Apache/2.3.0-dev (Unix)
# Apache/2.0.63 (FreeBSD) PHP/5.2.9 with Suhosin-Patch
# Apache/2.4.26 (FreeBSD)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:405:405:200:405:501:200:403:Apache/2.0 (Unix) or Apache/2.2 (Unix) or Apache 2.2 (FreeBSD) or Apache/2.3 (Unix):Apache/2\.(0\.(4[3-9]|[56][0-9])|2\.[0-9]|3\.O-dev|4\.16):Apache/2.0.43-2.3.0-dev (Unix) or Apache/2.4.16 (FreeBSD)
# Apache/2.0.52 (CentOS)
# Apache/2.0.54 (Debian GNU/Linux) mod_python/3.1.3 Python/2.3.5 PHP/5.0.5-Debian-0.8~sarge1 mod_perl/1.999.21 Perl/v5.8.4
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:404:Apache/2.0 (Unix):Apache/2\.0\.5[2-4]:Apache/2.0.52-2.0.54 (Linux)
# Apache/2.0.54 (Debian GNU/Linux) mod_ssl/2.0.54 OpenSSL/0.9.7d mod_auth_pgsql/2.0.1 mod_perl/1.999.21 Perl/v5.8.4
# Apache/2.2.3 (Unix) mod_ssl/2.2.3 OpenSSL/0.9.6b PHP/5.1.6
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:302:405:405:200:405:501:200:302:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[4-9]|2\.[0-3]):Apache/2.0.54-2.2.3 (Unix)
# Apache/2.2.8 (Win32) PHP/6.0.0-dev
# Apache/2.2.8 (Win32) PHP/5.2.6
# Apache/2.2.11 (Win32) PHP/5.2.6
# Apache/2.2.17 (Win32) mod_ssl/2.2.17 OpenSSL/0.9.8o PHP/5.3.4 mod_perl/2.0.4 Perl/v5.10.1
# Apache/2.2.21 (Win32) mod_ssl/2.2.21 OpenSSL/1.0.0e PHP/5.3.8 mod_perl/2.0.4 Perl/v5.10.1
HTM:HTM:200:200:200:200:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:404:Apache/2.2 (Win32):^Apache/2\.2\.([89]|1[0-7]|21) \(Win32\):Apache/2.2.8-2.2.21 (Win32)
# Apache/2.0.52 (CentOS)
# Apache/2.0.53 (Fedora)
HTM:HTM:200:200:200:501:200:HTM:HTM:400:400:400:404:403:403:200:405:405:200:404:Apache/2.0 (Unix):Apache/2\.0\.5[23] \((CentOS|Fedora)\):Apache/2.0.52-2.0.53 (Red Hat)
# Apache/2.0.40 (Red Hat Linux)
# Apache/2.0.48 (Fedora)
# Apache/2.0.50 (Fedora)
# Apache/2.0.51 (Fedora)
# Apache/2.0.53 (Fedora)
# Apache/2.0.54 (Fedora) [w/ PHP/5.0.4]
# Apache/2.0.54 (Debian GNU/Linux) DAV/2 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_perl/1.999.21 Perl/v5.8.4
# Apache/2.2.2 (Fedora)
# Apache/2.2.3 (Fedora)
# Apache/2.2.4 (Unix) DAV/2 mod_ssl/2.2.4 OpenSSL/0.9.8e PHP/4.4.7 mod_apreq2-20051231/2.5.7 mod_perl/2.0.2 Perl/v5.8.7
# Apache/2.2.14 (Unix) DAV/2 mod_ssl/2.2.14 OpenSSL/0.9.8l PHP/5.3.1 mod_apreq2-20090110/2.7.1 mod_perl/2.0.4 Perl/v5.10.1
HTM:HTM:200:200:200:200:200:HTM:HTM:400:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.[45][0-9]|2\.([0-9][^0-9]|1[0-4])):Apache/2.0.50-2.2.14 (Linux)
HTM:HTM:403:200:302:302:302:HTM:HTM:302:302:400:403:403:403:403:403:403:302:302:Apache/2.0 (Unix)::Apache/2.0.55 (Unix) Ganesh/2.2.0
# Apache/2.0.49 (Linux/SuSE)
# Apache/2.0.50 (Linux/SUSE)
# Apache/2.0.53 (Linux/SUSE)
# Apache/2.0.54 (Debian GNU/Linux) FrontPage/5.0.2.2635 mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-21 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_webapp/1.2.0-dev mod_perl/1.999.21 Perl/v5.8.4
# Apache/2.0.54 (Debian GNU/Linux) FrontPage/5.0.2.2635 mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-16 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_webapp/1.2.0-dev mod_perl/1.999.21 Perl/v5.8.4
# Apache/2.0.54 (Debian GNU/Linux) FrontPage/5.0.2.2635 mod_python/3.1.3 Python/2.3.5 PHP/4.3.10-21 mod_ssl/2.0.54 OpenSSL/0.9.7e mod_webapp/1.2.0-dev mod_perl/1.999.21 Perl/v5.8.4
# Apache/2.2
# Apache/2.2.3 (Linux/SUSE)
# Apache/2.4.10 (Linux/SUSE)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:501:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix) or Apache/2.4 (Linux/SUSE):Apache/2\.(0\.[45][0-9]|2|4\.10):Apache/2.0.50-2.4.10 (Linux)
# Apache/2.0.59 (Unix) PHP/4.4.4
# Apache/2.0.59 (NETWARE) mod_jk/1.2.15
# Apache/2.0.52 (NETWARE) PHP/5.0.3 mod_jk/1.2.6a
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:501:200:403:Apache/2.0 (Unix) or Apache/2.0 (NETWARE):Apache/2\.0\.5[2-9]:Apache/2.0.52-2.0.59 (Unix / NETWARE)
# Apache/2.0.52 (Red Hat)
# Apache/2.2.3 (Red Hat) [w/ PHP/5.1.6]
XML:XML:200:200:200:200:200:XML:XML:400:400:400:404:405:405:200:405:405:200:404:Apache/2.0 (Unix) or Apache/2.2 (Unix):Apache/2\.(0\.5[2-9]|2\.[0-3]):Apache/2.0.52-2.2.3 (Unix)
HTM:HTM:200:200:200:200:200:HTM:HTM:302:302:400:302:302:302:200:302:302:200:302:Apache/2.2 (Unix)::Apache/2.2.0 (Linux/SUSE)
HTM:HTM:200:200:200:501:200:XML:HTM:400:400:400:404:405:405:200:405:405:200:403:Apache/2.2 (Unix)::Apache/2.2.4 (FreeBSD) DAV/2
xxx:xxx:200:200:200:501:200:HTM:xxx:400:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Unix)::Apache/2.2.0 (Unix) DAV/2 PHP/4.4.2
# Apache/2.0.48 (Unix) PHP/4.3.9 mod_ssl/2.0.48 OpenSSL/0.9.6b DAV/2
# Apache/2.2.0 (Linux/SUSE) [w/ PHP/4.4.0]
HTM:HTM:200:200:200:200:200:HTM:HTM:200:200:400:200:200:200:200:200:200:200:200:Apache/2.0 (Unix) or Apache/2.2 (unix):Apache/2.(0.(4[89]|5[0-9])|2\.0):Apache/2.0.48-2.2.0 (Unix)
HTM:HTM:200:200:302:302:302:HTM:HTM:400:400:400:200:200:200:200:200:200:302:404:Apache/2.2 (Unix)::Apache/2.2.3 (Debian) mod_jk/1.2.18 PHP/5.2.0-8
#
# Apache/2.0.44 (Win32)
# Apache/2.0.47 (Win32)
# Apache/2.0.59 (Win32)
# Apache/2.0.63 (Win32)
# Apache/2.2.3 (Win32) PHP/5.1.6
# Apache/2.2.4 (Win32)
HTM:HTM:403:200:200:501:200:HTM:HTM:200:400:400:404:405:405:200:405:501:200:404::Apache/2\.(0\.(4[4-9]|[56][0-9])|2\.[0-4]) \(Win32\):Apache/2.0.44-2.2.4 (Win32)
# Apache/2.2.4 (Win32) DAV/2 mod_ssl/2.2.4 OpenSSL/0.9.8d mod_autoindex_color PHP/5.2.1 mod_jk/1.2.20 mod_perl/2.0.3 Perl/v5.8.8
# Apache/2.2.6 (Win32) DAV/2 mod_ssl/2.2.6 OpenSSL/0.9.8e mod_autoindex_color PHP/5.2.4
HTM:HTM:403:200:200:501:200:XML:HTM:200:400:400:404:405:405:200:405:405:200:404:Apache/2.2 (Win32):Apache/2\.2\.[4-6] \(Win32\):Apache/2.2.2-2.2.6 (Win32)
# Windows 7 running apache 2.2.14 (win32)
HTM:HTM:200:401:401:401:401:HTM:HTM:401:400:400:401:401:405:405:405:501:401:401:Apache/2.2 (Win32)::Apache/2.2.14 (Win32)
200:200:200:200:400:501:200:400:400:400:400:400:404:405:404:200:404:501:200:404:::Oracle-Application-Server-10g/10.1.2.0.2 Oracle-HTTP-Server OracleAS-Web-Cache-10g/10.1.2.0.2
# Indy/10.0.52
# Indy/9.00.10
200:200:---:200:200:200:---:---:---:200:200:200:---:---:---:---:---:---:404:404:Indy:^Indy/(9|10\.)[0-9.]+:Indy/9.00.10-10.0.52
400:400:501:VER:VER:400:501:501:501:200:404:400:---:501:501:501:501:501:200:200:::Ipswitch-IMail/6.00
# Ipswitch-IMail/7.15
# Ipswitch-IMail/8.05
VER:VER:501:VER:VER:VER:501:501:501:200:404:400:---:501:501:501:501:501:200:HTM:Ipswitch-IMail:^Ipswitch-IMail/[78]\.:Ipswitch-IMail/7.15-8.05
200:200:404:200:200:400:400:400:400:400:400:400:405:404:404:404:404:404:200:404:::Microsoft-IIS/4.0
# Microsoft-IIS/4.0
# Microsoft-IIS/5.0
200:200:200:200:200:400:400:400:400:400:400:400:200:200:200:200:200:200:200:200:Microsoft-IIS/4.0 or Microsoft-IIS/5.0:^Microsoft-IIS/[45]\.0:Microsoft-IIS/4.0-5.0
200:200:404:200:200:400:400:400:400:400:400:400:405:404:404:404:404:404:404:404:Microsoft-IIS/5.0::Microsoft-IIS/5.0 [w/ PHP/4.3.3 & ASP.NET]
# Netscape-Enterprise/3.0L
# Netscape-Enterprise/3.5.1G
200:HTM:200:400:200:500:400:400:400:404:404:400:500:401:401:200:500:400:404:403:Netscape/3:Netscape-Enterprise/3:Netscape-Enterprise/3.0L-3.5.1G
400:HTM:200:400:400:400:400:400:400:404:404:400:404:401:401:200:404:404:404:403:Netscape/3::Netscape-Enterprise/3.6 SP2
HTM:HTM:HTM:200:HTM:HTM:HTM:HTM:HTM:HTM:HTM:400:411:411:405:405:405:405:200:302:::nginx/0.5.24
200:200:501:200:200:200:501:501:501:200:501:200:501:501:501:501:501:501:400:400:::Xunlei Http Server/1.0
# Cerberus FTP 5.0.6, port 443
200:200:405:200:200:---:---:---:---:200:200:200:200:200:200:200:---:---:200:200:::CerberusFTPServer/5.0Server: CerberusFTPServer/5.0
# Cerberus FTP 5.0.6, port 10000
---:---:200:200:200:---:405:405:---:200:200:200:---:405:405:405:405:405:414:414:::gSOAP/2.8
# Fedora 22 Apache
# Fedora 23 Apache
# Fedora 25 Apache
HTM:HTM:200:403:403:501:403:400:400:400:400:400:404:405:405:200:405:405:403:404:Apache/2.4:^Apache/2\.4\.(18( \(Fedora\))? PHP\/5\.6\.(21|22)|23( \(Fedora\))?( PHP\/(5\.6\.2[3456789]|7\.0\.13))?):Apache/2.4.18 (Fedora) PHP/5.6.21-23 or Apache 2.4.23 (Fedora) or Apache 2.4.23 (Fedora) PHP/5.6.23-29 or Apache 2.4.23 (Fedora) PHP/7.0.13 [R]
# openSuSE 13.2 Tomcat 7.0.55
HTM:HTM:200:505:505:505:500:400:400:400:400:400:404:403:403:405:501:501:500:404:::Apache-Coyote/1.1 [R]
# Scientific Linux 6.7 Tomcat 6.0.24
---:---:400:505:505:505:400:400:400:400:400:400:400:400:400:405:400:400:400:400:::Apache-Coyote/1.1 [R]
HTM:HTM:200:505:505:505:200:---:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [R]
# RHEL 6.8 Tomcat 6.0.24
---:---:400:505:505:505:400:---:400:400:400:400:400:400:400:405:400:400:400:400:::Apache-Coyote/1.1 [R]
# Nessus WWW
400:400:405:505:400:400:400:400:400:400:400:200:411:405:405:405:405:405:403:403:::NessusWWW [R]
400:400:405:505:400:400:400:400:400:400:400:404:411:405:405:405:405:405:404:404:::NessusWWW [R]
400:400:405:505:400:400:400:400:400:405:405:200:411:411:405:405:405:405:404:400:::NessusWWW [R]
400:400:405:505:400:400:400:400:400:405:405:200:411:411:405:405:405:405:404:404:::NessusWWW [L]
---:---:400:400:400:400:400:400:400:400:400:400:400:400:400:400:400:400:400:400:::NessusWWW [L]
400:400:405:505:400:400:400:400:400:405:405:200:405:405:405:405:405:405:404:404:::NessusWWW [R]
# CentOS 5.11 Tomcat 5.5.23
---:---:400:505:505:505:---:---:---:400:400:400:400:400:400:405:400:400:400:400:::Apache-Coyote/1.1 [R]
# Debian 8 Tomcat 7.0.64
XML:XML:200:505:505:505:200:400:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [R]
# Debian 7.11 Tomcat 6.0.45
XML:XML:200:505:505:505:200:---:---:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [R]
# Debian 8.5 Tomcat 8.0.14
XML:XML:500:505:505:505:200:400:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [R]
# Fedora 21 Apache/2.4.16 (Fedora) PHP/5.6.15
200:200:200:200:200:501:403:HTM:HTM:400:400:400:404:405:405:200:405:405:403:404:::Apache/2.4.16 (Fedora) PHP/5.6.15 [R]
# Windows 2012r2 Node.js 0.12.7
---:200:404:200:---:---:---:---:---:---:---:200:404:404:404:404:404:404:404:404:::Node.js 0.12.7 [R]
# CentOS Embedded Tomcat via Sonarqube
HTM:HTM:200:505:505:505:200:400:400:400:400:400:404:404:404:405:501:501:404:404:::Apache-Coyote/1.1 [Sonarqube]
# Ubuntu MiniServe 1.791 via Webmin
---:---:200:---:---:---:200:---:---:200:200:200:200:400:200:405:200:400:200:200:::MiniServ/1.791 [Webmin]
# RHEL 4 32bit CUPS/1.1
403:403:200:505:400:400:403:400:400:405:405:403:403:403:403:403:400:400:400:400:::CUPS/1.1 [R]
# CentOS gunicorn/19.4.5
400:400:200:VER:400:400:200:400:200:200:200:200:200:200:200:200:200:200:200:200:::gunicorn/19.4.5 [R]
# RHEL 6 64bit lighttpd 1.4.35
400:400:200:505:400:501:400:400:400:404:404:400:411:404:404:404:404:404:404:404:::lighttpd/1.4.35 [R]
# CentOS Apache/2.2.15
HTM:HTM:404:200:200:200:200:HTM:HTM:400:400:400:200:200:200:200:200:200:200:200:::Apache/2.2.15 (CentOS) [R]
# Ubuntu 16.04 Apache/2.4.18 (Ubuntu)
HTM:HTM:200:200:200:501:200:400:400:400:400:400:404:405:405:405:405:501:200:404:::Apache/2.4.18 (Ubuntu) [R]
# Windows Selenium 2.48.1 with Jetty/5.1.x
HTM:HTM:403:403:403:403:---:---:---:403:400:400:403:403:403:403:403:403:403:403:::Jetty/5.1.x (Windows 7/6.1 amd64 java/1.8.0_73 [Selenium Standalone 2.48.1]
# FreeBSD 10.3 Apache/2.4.23
HTM:HTM:200:200:200:501:200:400:400:400:400:400:404:405:405:200:405:501:200:403:::Apache/2.4.23 (FreeBSD) [R]
# Fedora 24 Apache/2.4.23
200:200:200:200:200:200:200:200:400:200:200:200:200:200:200:200:200:200:200:200:::Apache/2.4.23 (Fedora) PHP/5.6.28 [R]
# Fedora 23 Tomcat 8.0.39
HTM:HTM:200:505:505:400:200:400:400:400:400:400:404:403:403:405:501:501:200:404:::Apache-Coyote/1.1 [L]
# Fedora 24 Apache/2.4.25
# RHEL Apache/2.4.25 PHP 5.4.16
HTM:HTM:200:400:400:400:400:400:400:400:400:400:404:405:405:200:405:405:403:404:Apache/2.4:^Apache/2\.4\.(6|25)( \(Fedora\)| \(Red Hat Enterprise Linux\))?( PHP\/5\.(6\.(29|30)|4\.16))?:Apache/2.4.25 (Fedora) PHP/5.6.29-30 or Apache/2.4.6 (Red Hat Enterprise Linux) PHP/5.4.16 [R]
# Apache Traffic Server
400:400:400:200:400:400:400:400:400:400:404:400:200:200:403:200:200:200:400:400:::ATS/7.0.0 [R]
# Debian 7 Apache/2.2.22
# Debian 8 Apache/2.4.10
# Ubuntu Apache/2.4.7
HTM:HTM:200:400:400:400:400:400:400:400:400:400:404:405:405:405:405:501:200:404:Apache 2.2 or Apache 2.4:^Apache/2\.(2\.22 \(Debian\)|4\.(7|10|25) (\(Ubuntu\)|\(Debian\))):Apache/2.2.22 (Debian) or Apache/2.4.10 (Debian) or Apache/2.4.25 (Debian) or Apache/2.4.7 (Ubuntu)
# GE Multilin Relays
200:200:---:200:200:---:200:200:200:HTM:---:200:---:---:---:---:---:---:HTM:200:::GE Industrial Systems UR [R] 
#End of list";

#### Start of main code

include('global_settings.inc');
include("misc_func.inc");
include("http.inc");
include("dump.inc");

## DEBUG
#if (COMMAND_LINE)
#{
#  foreach port(make_list(80, 8000, 8080))	# 9090, 6800...
#   if ((s = open_sock_tcp(port)) != 0) break;
#  if (!s) exit(0);
#  close(s);
#  # thorough_tests = 1;
#}
#else

if (safe_checks()) e = 0; else e = 1;
port = get_http_port(default: 80, embedded: e, dont_break: TRUE);

ver = int(get_kb_item("http/" + port));
no404 = get_kb_item("www/no404/" + port);

bad = 0;
if (COMMAND_LINE && ! debug_level) debug_level = 1;
verbose_test = experimental_scripts || report_verbosity > 1 || COMMAND_LINE;
if (verbose_test)
 debug_print('Verbose mode enabled (old behavior).\n');
else
 debug_print('Terse mode enabled (new behavior).\n');

if (http_is_dead(port: port))
{
 exit(0, "Web server is dead.");
}

####

outdated = 0;
plugintime = cvsdate2unixtime(date: "$Date: 2017/05/26 23:59:56 $");
if (plugintime > 0)
  outdated = (unixtime() - plugintime > 86400 * 60);	# Two months

####

debug_print(level: 2, '** Fingerprinting ', get_host_ip(), ':', port, ' **\n');

global_var	wa;	# Reused by "no200" detection

siglen = 80;	# IMPORTANT! Update this when request are added or removed!

timeout = 5;
function testreq1(port, request, no404, no200)
{
  local_var	s, i, j, c, h, b, wansp, wa_len, sl;
  local_var	connect_refused;
  local_var	t1, t2;

  sl = 1;
  if (thorough_tests) j = 2; else j = 1; # We try twice to get data in thorough_tests
# TEST
if (COMMAND_LINE) j = 3;
  while (j -- > 0 && !c)
  {
    if (thorough_tests) i = 3; else i = 1; # We try 3*2 times to connect to the server in thorough_tests
# TEST
if (COMMAND_LINE) i = 4;
    while (i -- > 0 && ! s)
    {
      s = http_open_socket(port);
      if (!s)
      {
        connect_refused ++;
        if (i <= 0) break;
        debug_print(level: 2, 'Connection refused - sleeping ', sl, ' s and retrying.\n');
        sleep(sl ++);
      }
      else
      {
        connect_refused = 0;
      }
    }
    if (s)
    {
      send(socket: s, data: request);
      t1 = unixtime();
      c = recv_line(socket: s, length: 1024, timeout: timeout);
      if (c)
      {
        h = http_recv_headers3(socket:s);
        b = http_recv_body(socket: s, headers: h);
      }
      else
      {
       t2 = unixtime();
       if (t2 - t1 < timeout) return '---';
      }
      http_close_socket(s); s = NULL;
    }
  }
  if (sl > 1)
  {
    if (c)
     debug_print('Problem reading data from ', get_host_ip(), '. Try to increase the timeouts.\n');
   }

  if (connect_refused)
  {
    debug_print('Connection refused on port ', port, ' - exiting.\n');
    exit(0);
  }
  if (! c) return '---';

  if (h)
    wa = strcat(c, h, '\r\n', b);	# Whole answer
  else
    wa = strcat(c, b);

  i = 0;
  wa_len = strlen(wa);
  while ( i < wa_len && (wa[i] == ' ' || wa[i] == '\t' || wa[i] == '\r' || wa[i] == '\n'))
    i ++;

  if ( i >= wa_len ) return NULL;

  # We truncate the string, because ereg functions do not work on big strings
  wansp = substr(wa, i, i + 2048);

  # Just a try. If it breaks anything, just remove this line
  # and change back BLK to xxx in the signatures
  # if (wa =~ '^[ \t\r\n]*$') return 'BLK';
  if (wansp == '') return 'BLK';

  debug_print(level: 4, 'code=', c, '\n');

  if (! ereg(string: c, pattern: "^HTTP(/[0-9]\.[0-9])? +[0-9][0-9][0-9] ") &&
      c !~ "^(HTTP/NESSUS)/[0-9A-Z.]* 5[0-9][0-9] ")
  {
    if (c =~ "^HTTP/[0-9A-Z.]* ")
      return 'VER';

    if (wansp =~ '^<\\?xml')
      return 'XML';	# Maybe I should return HTM ?

    if (wansp =~ '^<[ \t\r\n]*(HTML|TITLE|HEAD|BODY|SCRIPT|X-HTML|BR|HR|P)[ \t\r\n]*>' ||
	wansp =~ '^<[ \t\r\n]*(BODY|HTML|BR|HR|BGSOUND|FRAMESET)[ \t\r\n]+[A-Z\'"=*,#0-9.:/ \t\r\n-]*>' ||
	wansp =~ '^<[ \t\r\n]*META[ \t\r\n]' ||
	wansp =~ '^<[ \t\r\n]*(A|BASE)[ \t\r\n]+HREF[ \t\r\n]*=[ \t\r\n]*"' ||
	wansp =~ '<[ \t\r\n]*(PRE|H[1-9]|P|B)[ \t\r\n]*>.*<[ \t\r\n]*/(PRE|H[1-9]|P|B)[ \t\r\n]*>' ||
	wansp =~ '^<[ \t\r\n]*script +(type|language)=["\']?(text/javascript|JavaScript|jscript\\.encode)["\']?[ \t\r\n]*>?' ||
	wansp =~ '^<jsp:useBean +[A-Z"=#0-9 \t\r\n]*/>[ \t\r\n]*<[ \t\r\n]*HTML[ \t\r\n]*>' ||
	wansp =~ '^<!DOCTYPE +(HTML|doctype|PUBLIC)' ||
	wansp =~ '^<[ \t\r\n]SCRIPT +(SRC|LANGUAGE)="' ||
	wansp =~ '^<[ \t\r\n]*LINK[ \t\r\n]+rel="[a-z]+"' ||
	wansp =~ '<[ \t\r\n]*\\?php [^>]*>' ||
	wansp =~ '<[ \t\r\n]*CENTER[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*STYLE[ \t\r\n]+TYPE="text/css"[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*TABLE([ \t\r\n]+[A-Z]+=([0-9]+%?|[a-z]+))*[ \t\r\n]*>' ||
	wa =~ '<[ \t\r\n]*STYLE[ \t\r\n]*>\\.[a-z]+' ||
	wansp =~ '^<[ \t\r\n]*(BODY|HTML)[ \t\r\n]+lang="[^"]+">[ \t\r\n>]' ||
	wansp =~ '^<\\?php[ \t\r\n]' ||
	wansp =~ '<[ \t\r\n]*(PRE|H[1-9]|P|B)[ \t\r\n]*>[ \t\r\n]*<[ \t\r\n]*FONT([ \t\r\n]+SIZE="\\+?[0-9]+")?[ \t\r\n]*>' ||
	wansp =~ '<[ \t\r\n]*IFRAME[ \t\r\n]+SRC=.*>' || wansp =~ '<[ \t\r\n]*FRAMESET[ \t\r\n]*>' ||
	# If we get an HTML comment, there is a high probability that what
	# comes next is HTML
	wansp =~ '^<!--.*-->')
      return 'HTM';
    else if (wa =~ '501 Method not implemented')
      return 501;
    else
    {
      debug_print(level: 2, '**** Request ****\n', request, '**** answer ****\n', wansp, '****\n');
      return 'xxx';
    }
  }

  if (c =~ "^HTTP(/[0-9.]+)? 200" && no404 && no404 >< wa)
    return 404;
  if (c=~ "^HTTP(/[0-9.]+)? 404" && no200 && no200 >< wa)
    return 200;

  c = strstr(c, ' ');
  return int(substr(c, 1, 3));
}

function same_start(s1, s2)
{
  local_var	l, l2, i;

  l = strlen(s1);
  l2 = strlen(s2);
  if (l > l2) l = l2;

  for (i = 0; i < l; i ++)
   if (s1[i] != s2[i])
     return 0;
  return 1;
}

global_var	nreq, longestreq, longestreqtime;
nreq = 0; longestreq = 0; longestreqtime = 0;

function testreq(port, request, no404, no200)
{
  local_var	t1, t2, dt, t;

  nreq ++;
  if (debug_level > 0) { t1 = gettimeofday(); }
  t = testreq1(port: port, request: request, no404: no404, no200: no200);
  if (debug_level > 0)
  {
   t2 = gettimeofday();
   dt = difftime(t1: t1, t2: t2);
   if (dt > 500000)
    debug_print('Request #', nreq, ' took ', dt / 1000, ' ms.\n');
   if (dt > longestreqtime) { longestreqtime = dt; longestreq = nreq; }
  }
  return t;
}

function banner_is_informative(name)
{
 if (isnull(name) || name == '') return 0;
 if (name == 'Apache') return 0;

 # We cannot be more precise for those servers
 # If we get some information, we'll have to remove some names from this list
 if (name == 'micro_httpd' || name == 'Rational_Web_Platform'
  || name == 'BATM' || name == 'FTGate' || name == 'JRun Web Server'
  || name == 'aMule'
  || name == 'Kerio Personal Firewall' || name == 'Sunbelt Personal Firewall')
	return 1;

 if (name =~ '^[a-z _-]+$') return 0;
 return 1;
}

#### Banner

banner = get_http_banner(port: port);
if (isnull(banner))
{
  debug_print('Broken web server.\n');
  exit(0);
}
else
{
  # MA 2007-06-04: Renaud found that HMAP kills iTunes
  # The lethal request is "GET /\r\n\r\n" but any other request that does not have a third part is also toxic.
  # It should be declared as 'broken', but let's double-check, just in case...
  if (egrep(string: banner, pattern: '^DAAP-Server:[ \t]*iTunes/'))
  {
    exit(0, 'Server is iTunes; HMAP would kill it');
  }

  xheaders = ""; b = banner;
  for (i = 0; i < 9; i ++)	# Don't loop on kazillons of headers
  {
    # Interesting headers: X-Powered-By, Ms-Author-Via, ETag,
    # and Via (a proxy may disturb the signature)
    xx = egrep(pattern: '^(([a-zA-Z-]*Via)|(X-[a-zA-Z-]+)|ETag):', string: b);
    if (!xx) break;
    # egrep may return a multiline result
    foreach x (split(xx)) {
      b -= x;
      x -= '\r';
      xheaders += x;
    }
  }
  serverheader = egrep(pattern: '^Server:', string: banner, icase: 1);
}

# So far, this script is experimental. We enable it if there is no banner, or a simplified banner
if (! COMMAND_LINE && ! experimental_scripts && ! thorough_tests &&
    serverheader && banner_is_informative(name: serverheader))
{
 exit(0, "HTTP banner on port "+port+" is detailed enough.");
}

if (xheaders)
  debug_print(level: 1, 'Server=', serverheader, '\n**** X ****\n', xheaders, '***********\n');

if (serverheader)
{
  serverheader = ereg_replace(string: serverheader, pattern: "^Server: *(.*)$", replace: "\1", icase: 1);
  serverheader -= '\r\n';
}

#### Reference request

r = http_get(port: port, item: "/");
t = testreq(port: port, request: r, no404: no404);
no200="";

redir = NULL;
slash_is_forbidden = NULL;

if (! t)
{
  # Very unreliable!
  exit(0, 'Web server is dead or very slow.');
}
# MA 2007-06-05: this code has been dead for a long time...
# else if (t == 'H')
# {
#   if (ver > 9)
#   {
#     debug_print('hmap: inconsistent HTTP/0.9 answer with version ', ver, '\n');
#     exit(0);
#   }
#   ver = 9;
# }
else if (t == 301 || t == 302 || t == 303)
{
  debug_print('/ is redirected, signature may be unreliable.\n');
  redir = t;
  debug_print(level: 2, 'redir=', redir, '\n');
  bad ++;	# Is this so bad?
}
else if (t == 404)
{
  debug_print('/ is not found, expect problems.\n');
  # Try to fix
  no200 = egrep(string: wa, pattern: ".*(<h1>[^<]*</h1>).*", icase: 1);
  if (! no200)
    no200 = egrep(string: wa, pattern: ".*(<h2>[^<]*</h2>).*", icase: 1);
  if (no200)
    no200 = ereg_replace(string: no200, pattern: ".*(<h[12]>[^<]*</h[12]>).*", icase: 1, replace: "\1");
  if (no200) debug_print(level: 2, 'no200=', no200, '\n');
  if (! no200) bad ++;
}
else if (t == 401)
{
# Note that we should not do this with 403, because it might be returned by
# some servers which "forbid" some odd requests.
  slash_is_forbidden = "401";
}
else if (t != 200)
{
  debug_print('/ is forbidden or in error, expect problems (code=', t, ').\n');
  bad ++;
}

last_code = t;
broken_srv = 1;

####

h = get_host_name();

# Might be useful:
# 'HEAD /asdfasdfasdfasdfasdf/../ HTTP/1.0'	(thttpd 2.10 / 2.20)

reqL1 = make_list(
'GET / \r\n\r\n',				# HTTP/0.9 + space
'GET /\r\n\r\n',				# HTTP/0.9
'OPTIONS * HTTP/1.1\r\nHost: ' + h + '\r\n\r\n',# OPTIONS *
'GET / HTTP/3.14\r\nHost: ' + h + '\r\n\r\n',	# SciFi
'GET / HTTP/\r\n\r\n',				# Incomplete
'get / http/1.0\r\n\r\n',			# Lowercase method
'GET\t/\tHTTP/1.0\r\n\r\n',			# Tab separator
'GET/HTTP/1.0\r\n\r\n',				# No separator
'GET\n/\nHTTP/1.0\r\n\r\n',			# \n instead of blank
'GET \\ HTTP/1.0\r\n\r\n',			# Windows like URI
'HEAD .. HTTP/1.0\r\n\r\n',			# relative + forbidden
'GET / HTTP/1.1\r\n\r\n'			# Incomplete HTTP/1.1 request
);
###Useless
###'GET / HTTP/1.X\r\n\r\n',			# Alphanum HTTP version
##'GET / HTTP/1.0\r\n\r\n',			# HTTP/1.0
## Removed: always got 200
##'GET / HTTP/1.1\r\nHost: ' + h + '\r\n\r\n',	# HTTP/1.1
###Useless
###'GET\r\n\r\n',					# Very incomplete!
###Useless
###'GET / NESSUS/1.0\r\n\r\n',			# Unknown protocol
## Only distinguish userver/0.3 from userver/0.4
##'GET / HTTP/1.0\n\n',				# LF instead of CRLF
##Useless but for apt-proxy?
##'GET . HTTP/1.0\r\n\r\n',			# relative URI
## Not added: I thought that it might help recognize Netscape/4.1 from
## Netscape/6.0, but not always.
## 'HEAD /../ HTTP/1.0\r\n\r\n',		# forbidden


methods = make_list(
## GET & HEAD removed: always returned 404
	'POST',	# Dangerous - disabled in "safe checks" below
	'PUT', 'DELETE',
###Useless
###	'OPTIONS',
	 'TRACE',
## MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK
## returned the same results as COPY
	'COPY', 'SEARCH'
	);

# Dangerous requests
reqL2 = make_list(
strcat('GET ', crap(data: "////////", length: 1024), ' HTTP/1.0\r\n\r\n'),
strcat('GET ', crap(data: '/ABC', length: 2048), ' HTTP/1.0\r\n\r\n')
);

sign = "";
rawsign = "";

# Ignore safe_checks if server is supposed to be Apache
# (or anything else that is robust enough):
# 1. the server is not vulnerable to a too long request
# 2. we need such request to differentiate close versions or
#    configurations of Apache.
no_dangerous_req = safe_checks() && (serverheader !~ "^((.*Powered by )?Apache|IBM_HTTP_SERVER|Oracle|Lotus-Domino|Microsoft-IIS|CompaqHTTPServer)");

# Get authorization string - we do not support complex schemes here
a = get_kb_item("/tmp/http/auth/"+port);
if (! a)
 a = get_kb_item("http/auth");

nreq = 0;
foreach r (reqL1)
{
  if (a)
    r = str_replace(find: '\n', string: r, replace: '\n'+a+'\r\n', count: 1);
  t = testreq(port: port, request: r, no404: no404, no200: no200);
  if (isnull(t))
  {
    debug_print('Request #', nreq, ' failed somehow\n');
    if (!thorough_tests) exit(0);
    bad ++; t = '+++';
  }
  else if (t != last_code) broken_srv = 0;
  rawsign = strcat(rawsign, t, ":");
  if (t == redir || t == slash_is_forbidden) t = "200";
  sign = strcat(sign, t, ":");
}

foreach m (methods)
{
  if (no_dangerous_req && m == 'POST')
  {
    t = '+++';
    nreq ++;
  }
  else
  {
#    if (a)
#      r = str_replace(find: '\n', string: r, replace: '\n'+a+'\r\n', count: 1);
    r = http_get(item: "/" + rand_str(), port: port);
    r = ereg_replace(pattern: "^GET", replace: m, string: r);
    t = testreq(port: port, request: r, no404: no404, no200: no200);
    if (isnull(t))
    {
      debug_print('Request #', nreq, ' failed somehow.\n');
      if (!thorough_tests) exit(0);
      t = '+++'; bad ++;
    }
  }
  if (t != '+++' && t != last_code) broken_srv = 0;
  rawsign = strcat(rawsign, t, ":");
  if (t == redir || t == slash_is_forbidden) t = "200";
  sign = strcat(sign, t, ":");
}

foreach r (reqL2)
{
  if (! no_dangerous_req)
  {
    t = testreq(port: port, request: r, no404: no404, no200: no200);
    if (isnull(t))
    {
      debug_print('Request #', nreq, ' failed somehow\n');
      if (! thorough_tests) exit(0);
      t = '+++'; bad ++;
    }
    else if (t != last_code) broken_srv = 0;
    rawsign = strcat(rawsign, t, ":");
    if (t == redir || t == slash_is_forbidden) t = "200";
    sign = strcat(sign, t, ":");
  }
  else
  {
    nreq ++;
    rawsign += '+++:';
    sign += '+++:';
  }
}

if (strlen(sign) != siglen) {
  err_print('This script is badly broken: strlen(sig)=', strlen(sign), ' siglen=', siglen, '\n');
  exit(1);
}

debug_print('The longest (#', longestreq, ') request took ', longestreqtime / 1000, 'ms.\n');

debug_print('sign   = ', sign, '\n');
if (sign != rawsign) debug_print('rawsign= ', rawsign, '\n');

if (xheaders)
  debug_print('--- xheaders ---\n', xheaders, '----------------\n');
# 2006-05-18: replace wildcard +++ by ...
pat = '^' + str_replace(string: rawsign, find: '+++', replace: '...') + "[^:]*:";
s = egrep(string: fingerprints, pattern :  pat);
if (!s)
{
 pat = '^' + str_replace(string: sign, find: '+++', replace: '...') + "[^:]*:";
 s = egrep(string: fingerprints, pattern : pat);
}

# TBD: if Etag is present, there should be a way to match it.

if (broken_srv)
{
  exit(0);
}

#### Fuzzy match

global_var	differences, rawdifferences;

if (!s)
{
  results = split(sign, sep: ":", keep: 0);
  rawresults = split(rawsign, sep: ':', keep: 0);
  n1 = max_index(results);
  n2 = max_index(rawresults);
  if (n1 != n2)
  {
   err_print('n1=', n1, ' n2=', n2, ' - This script is badly broken, exiting.\n');
   exit(1);
  }

  foreach sig (split(fingerprints, keep: 0))
  {
    if (strlen(sig) > 0 && ! match(string: sig, pattern: "#*"))
    {
      v = split(substr(sig, 0, siglen-1), sep: ":", keep: 0);
      v2 = eregmatch(string: substr(sig, siglen), pattern: '^([^:]*):([^:]*):(.*)$');
      n2 = max_index(v);
      if (n2 != n1 || isnull(v2))
      {
       err_print('Invalid signature: n2=', n2, ' n1=', n1, '\n', sig);
       continue;
      }

      if (verbose_test || strlen(v2[1]) == 0)
       srv = v2[3] - '\n';
      else
       srv = v2[1];
      re = v2[2];
      diff = 0; rawdiff = 0;
      for (i = 0; i < n2; i ++)
        if (v[i] != '+++' && results[i] != '+++')
        {
          if (v[i] != results[i])
          {
            diff ++;
          }
          if (v[i] != rawresults[i])
	  {
            rawdiff ++;
	  }
        }
      if (isnull(differences[srv]) || differences[srv] > diff)
        differences[srv] = diff;
      if (isnull(rawdifferences[srv]) || rawdifferences[srv] > rawdiff)
        rawdifferences[srv] = rawdiff;

      if (rawdiff == 0 && !s)
      {
        debug_print('S=', rawsign, '\n matches: \nS=', sig, '\n');
        s = sig;
        break;
      }
      if (diff == 0 && !s)
      {
        debug_print('S=', rawsign, '\n matches: \nS=', sig, '\n');
        s = sig;
        break;
      }
    }
  }

  m = 999999;
  foreach d (differences) { if (d < m) m = d; }
  foreach d (rawdifferences) { if (d < m) m = d; }

  hyp = ""; prev = ""; nb_hyp = 0;
  foreach i (keys(differences))
    if (rawdifferences[i] == m)
    {
      if (i != prev)
        hyp = string(hyp, i, "\n");
      prev = i;
      nb_hyp ++;
    }
    else if (differences[i] == m)
    {
      if (i != prev)
        hyp = string(hyp, i, "\n");
      prev = i;
      nb_hyp ++;
    }
## display("nb_hyp=", nb_hyp, "\n");
}

set_kb_item(name: "www/hmap/"+port+"/signature", value: sign);
set_kb_item(name: "www/hmap/"+port+"/raw_signature", value: rawsign);

if (http_is_dead(port: port))
security_note(port: port, extra: "
It seems your web server stopped responding while it was being
tested.

Please send the following data to www-signatures@nessus.org :

" + "  - Sig : " + sign + '\n  - RawSig : ' + rawsign + '\n  - Server header : ' + serverheader);

if (islocalnet()) local = ' [L] '; else local = ' [R] ';

send_flag = 0;
if (s)
{
  s = chomp(s);
  v2 = eregmatch(string: substr(s, siglen), pattern: '^([^:]*):([^:]*):(.*)$');
  if (isnull(v2))
  {
    err_print('This script is broken - invalid signature: \n', s);
    exit(1);
  }
  srv2 = ereg_replace(string: v2[3], pattern: ' +\\[[^]]+\\]$', replace: '');
  if (verbose_test)
    srv = v2[3];
  else if (strlen(v2[1]) == 0)
    srv = srv2;
  else
    srv = v2[1];

  re = v2[2];
  re = ereg_replace(string: re, pattern: "^\^Apache",
                    replace: '^([A-Za-z_-]+(/[0-9.]+)?[ \t]+)?Apache');

  debug_print(level: 4, 'serverheader=', serverheader, '\nRE=', re, '\nSRV=', srv, '\nSRV2=', srv2, '\n');

  if (re)
    set_kb_item(name: "www/hmap/"+port+"/banner_regex", value: re);
  if (strlen(v2[3]) > 0)
    set_kb_item(name: "www/hmap/"+port+"/description", value: v2[3]);
  if (strlen(v2[1]) > 0)
    set_kb_item(name: "www/hmap/"+port+"/type", value: v2[1]);

  more_info = 1;
  if (! verbose_test)
    rep = strcat("This web server was fingerprinted as : ", srv);
  else
    if (! serverheader)
  {
    if (re == "^$")
      rep = strcat("This web server was fingerprinted as : ", srv);
    else
      rep = strcat("Although it tries to hide its version,
this web server was fingerprinted as : ", srv);
  }
  else if (	re && ereg(string: serverheader, pattern: re) ||
		! re && serverheader == srv2 )
  {
    rep = strcat("This web server was fingerprinted as : ", srv, "
which is consistent with the displayed banner : ", serverheader);
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 1);
  }
# Apache short banners are a special case
  else if ((! re || serverheader =~ "^Apache(/[1-9](\.[0-9]+)?)?$") && same_start(s1: serverheader, s2: srv))
  {
    rep = strcat("This web server was fingerprinted as : ", srv, "
This seems to be consistent with the displayed banner : ", serverheader);
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 1);
  }
  else
  {
    rep = strcat("This web server was fingerprinted as : ", srv, "
which is not consistent with the displayed banner : ", serverheader);
    more_info = 0;
    if (!bad)
      if (outdated)
      {
        rep = strcat(rep, '\n\nThis plugin seems out of date.\nYou should run nessus-update-plugins to get better results.');
      }
      else
      {
      rep += '\n\n' +
	"If you think that Nessus was wrong, please send this signature
to www-signatures@nessus.org :

" + sign + ":FIX:" + serverheader + local + '\n' + s + '\n';
      send_flag ++;
      if (xheaders)
        rep += 'Including these headers :\n\n' + xheaders;
      rep += "
Try to provide as much information as you can - software & operating
system release, sub-version, patch numbers, and specific configuration
options, if any.";
      }
    set_kb_item(name: "www/hmap/"+port+"/banner_ok", value: 0);
  }

  if (! outdated && ! send_flag && strlen(serverheader) > 0)
  {
  if ("+++" >!< sign && "+++" >< s)
    rep += "

You found a better signature than the already known one.
Please send this to www-signatures@nessus.org :
" + sign + '::' + serverheader + local + '\n' + s + '\n';

  else if (report_verbosity > 9999 &&	# Disabled for the moment!
	more_info && srv =~ "^[A-Z_ -]+(/[0-9]+(\.[0-9])?)?$")
    rep += "

If you can provide more information about the server software and
operating system versions, specific configuration options, modules,
service packs, hotfixes, patches, etc., please send them to
www-signatures@nessus.org with this signature :
" + sign + "DETAILS:" + serverheader + local + '\n';
  }

  security_note(port: port, extra: '\n' + rep);
  debug_print(rep);
  exit(0);
}

####

if (m > 3 && bad && ! verbose_test)
{
  debug_print('Highly unreliable signature. Best match differs on ', m, 'points. Exiting silently.\n');
  exit(0, "Unreliable HMAP signature.");
}

if (bad)
 rep = 'Nessus was not able to reliably identify this server.';
else
 rep = 'Nessus was not able to exactly identify this server.';

rep = strcat(rep, ' It might be :\n',
        '\n',
	hyp,
        '\n',
        'The fingerprint differs from the known signatures on ',
	m, ' point(s).\n');

# Should I store these results in the KB?

####

if (!bad || COMMAND_LINE)
{
  rep = rep + '
If you know what this server is and if you are using an up to date version
of this script, please send this signature to www-signatures@nessus.org :

' + sign + '::' + serverheader + local + '\n';
  if (rawsign != sign)
    rep = strcat(rep, rawsign, ':RAW:', serverheader, '\n');
  if (xheaders)
    rep = rep + 'Including these headers :\n\n' + xheaders;
 rep += '
Try to provide as much information as you can - software & operating
system release, sub-version, patch numbers, and specific configuration
options, if any.';
}

security_note(port: port, extra:'\n'+rep);
