#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20253);
  script_version("$Revision: 1.21 $");
  script_cve_id("CVE-2005-3976", "CVE-2006-6354", "CVE-2006-6367");
  script_bugtraq_id(15681, 21405);
  script_osvdb_id(21385, 31724, 31728);

  script_name(english:"DUware Multiple Products type.asp iType Parameter SQL Injection");
  script_summary(english:"Checks for iType parameter SQL injection vulnerability in DUware");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server has an ASP application that is affected by a SQL
injection flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an ASP application from DUware such as
DUamazon, DUarticle, DUclassified, DUdirectory, DUdownload, DUgallery,
DUnews or DUpaypal. 

The installed version of that application does not validate input to
the 'iType' parameter of the 'inc_type.asp' script before using it in
a database query.  An attacker may be able to leverage this issue to
manipulate SQL queries. 

Additional scripts are reported to be vulnerable to SQL injection as
well." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/02");
 script_cvs_date("$Date: 2016/12/06 20:34:49 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/amazon", "/articles", "/calendar", "/classified", "/directory", "/gallery", "/news", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  r = http_send_recv3(port: port, method: "GET", 
   item:string(
      dir, "/type.asp?",
      "iType='", SCRIPT_NAME ));
  if (isnull(r)) exit(0);

  # There's a problem if we see a syntax error and our script name.
  if (
    "Syntax error" >< r[2] &&
    egrep(pattern:string("_TYPE = ''", SCRIPT_NAME), string:r[2])
  ) {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
