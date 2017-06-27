#
# (C) Tenable Network Security, Inc.
#

# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: this domain no longer exists)
#      Added link to the Bugtraq message archive
#
# References:
# Date:  Thu, 05 Jul 2001 03:41:50 -0400
# From: "KF" <dotslash@snosoft.com>
# To: bugtraq@securityfocus.com, recon@snosoft.com
# Subject: Cobalt Cube Webmail directory traversal
#

include("compat.inc");

if (description)
{
 script_id(11073);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2001-1408");
 script_osvdb_id(8983);

 script_name(english:"Cobalt Qube WebMail readmsg.php mailbox Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of Cobal Cube webmail");

 script_set_attribute(attribute:"synopsis", value:
"The web application running on the remote host has a directory
traversal vulnerability.");
 script_set_attribute(attribute:"description", value:
"The file '/base/webmail/readmsg.php' was detected on the remote web
server. Some versions of this CGI allow remote users to read local
files with the permission of the web server.

*** Nessus just checked the presence of this file *** but did not try
to exploit the flaw.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/92");
 script_set_attribute(attribute:"solution", value:"Upgrade to the latest version of this software.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 444);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);

res = is_cgi_installed3(item:"/base/webmail/readmsg.php", port:port);
if( res ) security_warning(port);

# The attack is:
# http://YOURCOBALTBOX:444/base/webmail/readmsg.php?mailbox=../../../../../../../../../../../../../../etc/passwd&id=1
