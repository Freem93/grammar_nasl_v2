#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added CAN.  Added link to the Bugtraq message archive
#
# References:
# From: joetesta@hushmail.com
# To: bugtraq@securityfocus.com, jscimone@cc.gatech.edu
# Subject: Vulnerabilities in PGPMail.pl
# Date: Thu, 29 Nov 2001 19:45:38 -0800
#
# John Scimone <jscimone@cc.gatech.edu>.
# <http://www.securityfocus.com/archive/82/243262>
#

include("compat.inc");

if (description)
{
 script_id(11070);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2016/11/23 20:42:23 $");

 script_cve_id("CVE-2001-0937");
 script_bugtraq_id(3605);
 script_osvdb_id(11968);
 script_name(english:"PGPMail.pl detection");
 script_summary(english:"Checks for the presence of PGPMail.pl");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands might be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"The 'PGPMail.pl' CGI is installed.

Some versions (up to v1.31 a least) of this CGI do not properly filter
user input before using it inside commands. This would allow an
attacker to run any command on the server.

Note: Nessus just checked the presence of this CGI but did not try to
exploit the flaws.");
 script_set_attribute(attribute:"solution", value:"remove it from /cgi-bin or upgrade it.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/82/243262");
 script_set_attribute(attribute:"see_also", value:"http://online.securityfocus.com/archive/1/243408");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/13");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80, embedded: 0);
res = is_cgi_installed3(port:port, item:"PGPMail.pl");
if(res) security_hole(port);

