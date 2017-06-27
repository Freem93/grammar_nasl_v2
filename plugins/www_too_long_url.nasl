#
# (C) Tenable Network Security, Inc.
#

# Some vulnerable servers:
# SmallHTTP (All versions vulnerable: 2.x Stables, 3.x Latest beta 8)
# OmniHTTPd v2.09 of Omnicron (www.omnicron.ca)
# MyWebServer 1.02
# atphttpd-0.4b ?
# IBM Tivoli Management Framework < Currently Fixpack 2 or Patches 3.7.1-TMF-0066
#   LCFD process - default port 9495)
# IBM Tivoli Management Framework 3.6.x through 3.7.1 (fixed in 4.1)
#   Spider process - default port 94 redirected to another port.
# Lucent Access Point IP Services Router (Formerly known as Xedia Router)
# Oracle9iAS Web Cache/2.0.0.1.0
# TelCondex SimpleWebServer 2.06.20817 Build 3128
# WebServer 4 Everyone
# WebServer 4 Everyone v1.28 (if Host field is set)
# Savant Web Server 3.1 and previous
# WN Server 1.18.2 through 2.0.0 (upgrade to 2.4.4)
# Multitech RouteFinder 550 VPN  (upgrade to RF550VPN_V463)
# Web Server 4D/eCommerce 3.5.3
# ZBServer Pro 1.50-r13
# BRS WebWeaver 1.03
# U.S. Robotics Broadband-Router 8000A/8000-2 (USR848000A-02) running firmware version 2.5
# Polycomm ViaVideo Web component 2.2 & 3.0
# GazTek HTTP Daemon v1.4-3
# WebFS 1.20
# UltraVNC <= 1.0.1
#
########################
# References:
########################
#
# Date: Sat, 12 Oct 2002 07:49:52 +0200
# From:"Marc Ruef" <marc.ruef@computec.ch>
# To:bugtraq@securityfocus.com
# Subject: Long URL crashes My Web Server 1.0.2
#
# Date: Sun, 13 Oct 2002 15:00:18 +0200
# From:"Marc Ruef" <marc.ruef@computec.ch>
# To:bugtraq@securityfocus.com
# Subject: Long URL causes TelCondex SimpleWebServer to crash
#
# Date: Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:advisory@prophecy.net.nz
# To:bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
# From:"David Endler" <dendler@idefense.com>
# To:bugtraq@securityfocus.com
# Date: Tue, 15 Oct 2002 13:12:35 -0400
# Subject: iDEFENSE Security Advisory 10.15.02: DoS and Directory Traversal Vulnerabilities in WebServer 4 Everyone
#
# Delivered-To: mailing list vulnwatch@vulnwatch.org
# Date: Tue, 10 Sep 2002 15:39:02 -0700
# Message-ID: <9DC8A3D37E31E043BD516142594BDDFA017CA6FC@MISSION.foundstone.com>
# From: "Foundstone Labs" <labs@foundstone.com>
# To: "announce" <announce@foundstone.com>
# Subject: Foundstone Labs Advisory - Buffer Overflow in Savant Web Server
#
# From:"David Endler" <dendler@idefense.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 30 Sep 2002 10:09:59 -0400
# Subject: iDEFENSE Security Advisory 09.30.2002: Buffer Overflow in WN Server
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: Web Server 4D/eCommerce 3.5.3 DoS Vulnerability
# Date: Tue, 15 Jan 2002 00:35:59 +0200
# Affiliation: http://www.securityoffice.net
#
# From: "Tamer Sahin" <ts@securityoffice.net>
# To: bugtraq@securityfocus.com
# Subject: ZBServer Pro DoS Vulnerability
# Date: Tue, 15 Jan 2002 04:44:37 +0200
# Affiliation: http://www.securityoffice.net
#
# Date:	 Mon, 14 Oct 2002 08:27:54 +1300 (NZDT)
# From:	advisory@prophecy.net.nz
# To:	bugtraq@securityfocus.com
# Subject: Security vulnerabilities in Polycom ViaVideo Web component
#
# Date: Sat, 12 Oct 2002 17:02:31 -0700
# To: bugtraq@securityfocus.com
# Subject: Pyramid Research Project - ghttpd security advisorie
# From: pyramid-rp@hushmail.com
#
# Date: Tue Apr 04 2006 - 14:24:13 CDT
# To: bugtraq@securityfocus.com
# Subject: Buffer-overflow in Ultr@VNC 1.0.1 viewer and server
# From: Luigi Auriemma (aluigiautistici.org)
#
########################

include("compat.inc");

if (description)
{
 script_id(10320);
 script_version("$Revision: 1.74 $");
 script_cvs_date("$Date: 2016/02/05 14:39:33 $");

 script_cve_id(
  "CVE-2000-0002",
  "CVE-2000-0065",
  "CVE-2000-0571",
  "CVE-2000-0641",
  "CVE-2001-0820",
  "CVE-2001-0836",
  "CVE-2001-1250",
  "CVE-2002-0123",
  "CVE-2002-1003",
  "CVE-2002-1011",
  "CVE-2002-1012",
  "CVE-2002-1120",
  "CVE-2002-1166",
  "CVE-2002-1212",
  "CVE-2002-1905",
  "CVE-2002-2149",
  "CVE-2003-0125",
  "CVE-2003-0833",
  "CVE-2004-2299",
  "CVE-2005-1173",
  "CVE-2006-1652"
 );
 script_bugtraq_id(
  889,
  1423,
  2979,
  6994,
  7067,
  7280,
  8726,
  17378
 );
 script_osvdb_id(
  1172,
  1442,
  1456,
  3996,
  5370,
  5534,
  6660,
  6767,
  6768,
  7584,
  8809,
  9829,
  9836,
  11788,
  11789,
  12405,
  12944,
  14511,
  15667,
  18122,
  24456,
  51573,
  56515,
  57529,
  57532,
  57533
 );

 script_name(english:"Web Server Long URL Handling Remote Overflow DoS");
 script_summary(english:"Web server buffer overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by a buffer overflow
vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote web server crashes when it receives a too long URL. It
might be possible to make it execute arbitrary code through this flaw.");
 script_set_attribute(attribute:"solution", value:"Contact the web server's author / vendor for a patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'UltraVNC 1.0.1 Client Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
# All the www_too_long_*.nasl scripts were first declared as
# ACT_DESTRUCTIVE_ATTACK, but many web servers are vulnerable to them:
# The web server might be killed by those generic tests before Nessus
# has a chance to perform known attacks for which a patch exists
# As ACT_DENIAL are performed one at a time (not in parallel), this reduces
# the risk of false positives.

 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie('http_version.nasl', 'www_multiple_get.nasl');
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded:1);

if (http_is_dead(port:port))exit(1, "The web server on port "+port+" is dead");

# Try to avoid FP on CISCO 7940 phone
max = get_kb_item('www/multiple_get/'+port);
if (max)
{
 imax = max * 2 / 3;
 if (imax < 1)
  imax = 1;
 else if (imax > 5)
  imax = 5;
}
else
 imax = 5;
debug_print('imax=',imax,'\n');

# vWebServer and Small HTTP are vulnerable *if* the URL is requested
# a couple of times. Ref: VULN-DEV & BUGTRAQ (2001-09-29)
for (i = 0; i < imax; i = i + 1)
{
 r = http_send_recv3(port: port, method: 'GET', item: strcat('/', crap(65535)));
}


if(http_is_dead(port: port, retry:3))
{
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
}
