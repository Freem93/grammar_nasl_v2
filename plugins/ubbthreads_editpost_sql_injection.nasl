#
# (C) Tenable Network Security
#


include("compat.inc");

if (description) {
  script_id(17316);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0726");
  script_bugtraq_id(12784);
  script_osvdb_id(14744);

  script_name(english:"UBB.threads editpost.php Number Parameter SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote host is running a version of
UBB.threads that fails to sufficiently sanitize the 'Number' parameter
before using it in SQL queries in the 'editpost.php' script.  As a
result, a remote attacker can pass malicious input to database
queries, potentially resulting in data exposure, modification of the
query logic, or even data modification or attacks against the database
itself." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111056135818279&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to UBB.threads version 6.5.1.1 or greater." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/11");
 script_cvs_date("$Date: 2011/03/15 19:26:56 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for SQL injection vulnerability in UBB.threads editpost.php");
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");

  script_dependencies("ubbthreads_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ubbthreads");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/ubbthreads"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  # nb: actually exploiting this generally requires you be be editing your
  #     own post, and most boards require posters to authenticate first.
  #
  # nb: the changelog claims the vulnerability was fixed in 6.5.1.1 so
  #     we should assume everthing below that is vulnerable.
  if (ver =~ "^([0-5]\.|6\.([0-4][^0-9]|5$|5\.0|5\.1([^0-9.]|$)))") 
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  }
}
