#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(55133);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_name(english:"Active Directory Certificate Services Web Enrollment Anonymous Access");
  script_summary(english:"Checks out /certsrv");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is a certificate enrollment server that anyone
can access without credentials.");
  script_set_attribute(attribute:"description", value:
"The remote web server is running the Microsoft Certificate Services.

However, the service is misconfigured in such a way that anonymous
users can log into the service to request certificates, thus breaking
the chain of trust." );
  script_set_attribute(attribute:"solution", value:
"Edit the remote web server configuration to force authentication prior to accessing
the remote resource." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");


  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");


port = get_http_port(default:80);

r = http_send_recv3(method:"GET", port: port, item:"/certsrv/", exit_on_fail:TRUE);
if ( r[0] =~ "HTTP/.* 200 " &&
     "<Title>Microsoft Certificate Services</Title>" >< r[2] &&
     "Use this Web site to request a certificate for your Web browser," >< r[2] )
 {
      installs = add_install(
      appname  : "ms_cert_srv",
      port     : port,
      dir      : "/certsrv",
      ver      : "unknown"
    );

   report = get_install_report(
    port         : port,
    installs     : installs,
    display_name : "Microsoft Certificate Services"
  );
  if (  get_kb_item("http/login") == NULL ||  get_kb_item("http/password") == NULL )
	security_warning(port:port, extra:report);
 }
else exit(0, "The web server on port "+port+" is not running Microsoft Certificate Services.");
