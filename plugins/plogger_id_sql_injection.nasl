#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(29746);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-6587");
  script_bugtraq_id(26958);
  script_osvdb_id(39764);

  script_name(english:"Plogger plog-rss.php id Parameter SQL Injection");
  script_summary(english:"Tries to generate a SQL error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Plogger, an open source photo
gallery written in PHP. 

The version of Plogger installed on the remote host fails to sanitize
input to the 'id' parameter of the 'plog-rss.php' script before using
it in a database query.  Regardless of PHP's 'magic_quotes_gpc' and
'register_globals' settings, an attacker may be able to exploit this
issue to manipulate database queries, leading to disclosure of
sensitive information, modification of data, or attacks against the
underlying database." );
  # http://web.archive.org/web/20080705090019/http://www.mwrinfosecurity.com/publications/mwri_plogger-photo-gallery-sql-injection-vulnerability_2007-12-17.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?106be9e9" );
 # https://web.archive.org/web/20081201005840/http://dev.plogger.org/changeset/489
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?942daa07" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Plogger 1.0 beta 3.0 if necessary and apply change set 489." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/23");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:plogger:plogger");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

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

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/plogger", "/gallery", "/photos", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue to generate a SQL error.
  exploit = string("999 OR ", SCRIPT_NAME);

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/plog-rss.php?",
      "level=collection&",
      "id=", urlencode(str:exploit)));
  if (isnull(r)) exit(0);
  res = r[2];

  # There's a problem if we see a SQL error involving our exploit
  if (string("WHERE p.`parent_collection` = ", exploit) >< res)
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
