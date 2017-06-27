#
# (C) Tenable Network Security, Inc.
#
# References:
# From: "karol _" <su@poczta.arena.pl>
# To: bugtraq@securityfocus.com
# CC: arslanm@Bilkent.EDU.TR
# Date: Fri, 06 Jul 2001 21:04:55 +0200
# Subject: basilix bug
#

include("compat.inc");

if (description)
{
 script_id(11072);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2001-1045");
 script_bugtraq_id(2995);
 script_osvdb_id(8956);

 script_name(english:"Basilix Webmail basilix.php3 request_id[DUMMY] Variable Traversal Arbitrary File Access");
 script_summary(english:"Checks for the presence of basilix.php3");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a remote
file include attack.");
 script_set_attribute(attribute:"description", value:
"The script 'basilix.php3' is installed on the remote web server. Some
versions of this webmail software allow the users to read any file on
the system with the permission of the webmail software, and execute
any PHP.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jul/114");
 script_set_attribute(attribute:"solution", value:"Update Basilix or remove DUMMY from lang.inc.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/07/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencies("http_version.nasl", "logins.nasl");
 script_require_keys("imap/login", "imap/password", "Settings/ParanoidReport", "www/PHP");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass)
  exit(1, "imap/login and/or imap/password are empty");


url=string("/basilix.php3?request_id[DUMMY]=../../../../../../../../../etc/passwd&RequestID=DUMMY&username=", user, "&password=", pass);
if(is_cgi_installed3(port:port, item:url)){ security_hole(port); exit(0); }
