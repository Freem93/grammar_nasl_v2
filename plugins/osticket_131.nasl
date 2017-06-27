#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18612);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2014/05/26 01:50:29 $");

  script_cve_id("CVE-2005-2153", "CVE-2005-2154");
  script_bugtraq_id(14127);
  script_osvdb_id(17714, 17715, 17716, 17717);

  script_name(english:"osTicket <= 1.3.1 Multiple Vulnerabilities");
  script_summary(english:"Checks version of osTicket");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is prone to
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of osTicket installed on the remote host suffers from
several vulnerabilities, including:

  - A Local File Include Vulnerability
    The application fails to sanitize user-supplied input
    to the 'inc' parameter in the 'view.php' script. An
    attacker may be able to exploit this flaw to run
    arbitrary PHP code found in files on the remote host
    provided PHP's 'register_globals' setting is enabled.

  - A SQL Injection Vulnerability
    An authenticated attacker can affect SQL queries via
    POST queries due to a failure of the application to
    filter input to the 'ticket' variable in the
    'class.ticket.php' code library.");
  # http://web.archive.org/web/20070109202846/http://www.osticket.com/forums/showthread.php?t=1283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6215efd9");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/403990/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Jul/9");
  script_set_attribute(attribute:"solution", value:"Apply the security update for version 1.3.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/05");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:osticket:osticket_sts");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

  script_dependencies("osticket_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("Settings/ParanoidReport", "www/osticket");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# nb: the vendor has issued a patch that doesn't change the version.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/osticket"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # Check the version number -- both flaws require authentication.
  if (ver && ver  =~ "^(0\.|1\.([01]\.|2\.[0-7]|3\.[01]))") {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
