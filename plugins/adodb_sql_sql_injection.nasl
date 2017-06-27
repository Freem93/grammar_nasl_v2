#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20385);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2011/09/14 19:48:34 $");

  script_cve_id("CVE-2006-0146");
  script_bugtraq_id(16187);
  script_osvdb_id(22290);

  script_name(english:"ADOdb server.php sql Parameter SQL Injection");
  script_summary(english:"Checks for sql parameter SQL injection vulnerability in ADOdb");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server has a PHP script that is affected by a SQL
injection flaw.");
  script_set_attribute(attribute:"description", value:
"The remote host is running ADOdb, a database abstraction library for
PHP. 

The installed version of ADOdb includes a test script named
'server.php' that fails to sanitize user input to the 'sql' parameter
before using it in database queries.  An attacker can exploit this
issue to launch SQL injection attacks against the underlying database.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-64/advisory/");
  script_set_attribute(attribute:"solution", value:
"Remove the test script or set a root password for MySQL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/01/10");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
# if ( !thorough_tests ) exit(0);


subdirs = make_list(
  "/adodb",                            # PHPSupportTickets
  "/core/adodb",                       # Mantis
  "/includes/third_party/adodb",       # Cerberus
  "/lib/adodb",                        # Cacti / Moodle / TikiWiki
  "/library/adodb",                    # dcp_portal
  "/libraries/adodb",                  # phpPgAdmin
  "/xaradodb"                          # Xaraya
);


# Loop through directories.
foreach dir (cgi_dirs()) {
  foreach subdir (subdirs) {
    # Try to exploit the flaw to generate a syntax error.
    cgi = strcat(dir, subdir, "/server.php");
    u = strcat(cgi, "?sql='", SCRIPT_NAME);
    r = http_send_recv3(port: port, method: "GET", item: u);
    if (isnull(r)) exit(0);

    # There's a problem if we get a syntax error involving our script name.
    if (egrep(pattern:"an error in your SQL syntax.+ near ''" + SCRIPT_NAME, string:r[2])) {
      info = strcat('\nThe vulnerable CGI is reachable at:\n', build_url(port: port, qs: cgi), '\n\n');
      security_hole(port:port, extra: info);
      if (COMMAND_LINE) display(info);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
