#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24322);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2007-0853");
  script_bugtraq_id(22460);
  script_osvdb_id(33121);

  script_name(english:"DevTrack Web Service UserName Field SQL Injection");
  script_summary(english:"Tries to generate a SQL error using DevTrack Web Service");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is affected by
a SQL injection vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running DevTrack, a defect and project tracking
tool. 

The DevTrack Web Services component installed on the remote host
contains an ASP script that fails to sanitize user-supplied input to
the 'UserName' parameter before using it in a database query.  An
unauthenticated, remote attacker may be able to leverage this flaw to
manipulate SQL queries and uncover sensitive information, modify data,
or even launch attacks against the underlying database." );
 script_set_attribute(attribute:"solution", value:
"The vendor is rumoured to be incorporating a fix into DevTrack version
6.2." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/02/08");
 script_cvs_date("$Date: 2016/05/05 16:01:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:techexcel_inc.:devtrack");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);


# Loop through various directories.
#
# nb: the app uses "/TXWebService" by default so make sure we do too.
dirs = list_uniq(make_list("/TXWebService", cgi_dirs()));

foreach dir (dirs)
{
  # Try to generate a SQL error.
  exploit = string("'nessus", unixtime());
  r = http_send_recv3(method: "GET", port: port, item:string(
      dir, "/DataService.asmx/AuthUser?",
      "UserName=", urlencode(str:exploit), "&",
      # nb: leave it empty to return data.
      "Password=nasl&",
      "NeedCompress=0"
    ));
  if (isnull(r)) exit(0);

  # There's a problem if we see a SQL error.
  if (
    "ReturnMessage>Database Error" >< r[2] &&
    string("Incorrect syntax near ", exploit, "'") >< r[2]
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
