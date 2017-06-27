#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID

# Source:
# From:"Peter_Grundl" <pgrundl@kpmg.dk>
# To:"bugtraq" <bugtraq@securityfocus.com>
# Subject: KPMG-2002033: Resin DOS device path disclosure
# Date: Wed, 17 Jul 2002 11:33:59 +0200

include("compat.inc");

if (description)
{
 script_id(11048);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2016/05/26 16:14:08 $");

 script_cve_id("CVE-2002-2090");
 script_bugtraq_id(5252);
 script_osvdb_id(850);

 script_name(english:"Resin MS-DOS Device Request Path Disclosure");
 script_summary(english:"Tests for Resin path disclosure vulnerability");

 script_set_attribute(attribute:"synopsis", value:"It is possible to disclose information about the remote host.");
 script_set_attribute(attribute:"description", value:
"Resin will reveal the physical path of the webroot when asked for a
special DOS device, e.g.  lpt9.xtp

An attacker may use this flaw to gain further knowledge about the
remote filesystem layout.");
 script_set_attribute(attribute:"solution", value:"Upgrade to a later software version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/07/17");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:caucho_technology:resin");
 script_end_attributes();

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("iis_detailed_error.nasl", "404_path_disclosure.nasl");
 script_require_ports("Services/www", 8080, 8282);
 script_require_keys("www/resin");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8282);
if (get_kb_item("www/"+port+"/iis_detailed_errors"))  exit(0, "The web server listening on port "+port+" appears to be an instance of IIS that returns detailed error messages.");
if (get_kb_item("www/"+port+"/generic_path_disclosure"))  exit(0, "The web server listening on port "+port+" is known to be affected by a generic path disclosure vulnerability.");


# Requesting a DOS device may hang some servers
# According to Peter Grundl's advisory:
# Vulnerable:
# Resin 2.1.1 on Windows 2000 Server
# Resin 2.1.2 on Windows 2000 Server
# <security-protocols@hushmail.com> added Resin 2.1.0
# Not Vulnerable:
# Resin 2.1.s020711 on Windows 2000 Server
#
# The banner for snapshot 020604 looks like this:
# Server: Resin/2.1.s020604

if (report_paranoia < 2)
{
  banner = get_http_banner(port: port, exit_on_fail:TRUE);
  if ("Resin" >!< banner) exit(1, "The web server listening on port "+port+" does not appear to be Resin.");
}

url = "/aux.xtp";

res = test_generic_path_disclosure(item: url,
                                   method: "GET",
                                   port: port,
                                   path_type: "windows",
                                   filename: "aux.xtp",
                                   exit_on_fail: TRUE);

if (!res) exit(0, "The web server listening on port "+port+" is not affected.");
