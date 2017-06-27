#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Graylog2 Default Credentials");
  script_summary(english:"Checks for default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is using a known set
of default credentials.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Graylog2, a log collection and analysis
system, which is using a known set of default credentials.");
  script_set_attribute(attribute:"see_also", value:"https://www.graylog2.org/");
  script_set_attribute(attribute:"solution", value:"Change the default credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:torch_gmbh:graylog2");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("graylog2_web_interface_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 443);
  script_require_keys("installed_sw/Graylog2");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

get_install_count(app_name:'Graylog2', exit_if_zero:TRUE);

port = get_http_port(default:443);

install = get_single_install(
  app_name : 'Graylog2',
  port     : port
);

user = 'admin';
pass = 'password';

postdata = 'destination=%2Fstartpage&username=' + user + '&password=' + pass + '&submit=';

res = http_send_recv3(
  item            : "/login",
  method          : "POST",
  port            : port,
  content_type    : "application/x-www-form-urlencoded",
  exit_on_fail    : TRUE,
  data            : postdata
);

if(res[1] =~ "(^|[\n\r])\s*Location\s*:\s*/startpage[\s\n\r]" &&
   res[1] =~ "[\n\r]\s*Set-Cookie\s*:[^\n\r]*PLAY_SESSION\s*=")
{
  if(report_verbosity > 0)
  {
    report = '\nNessus was able to log into Graylog2 using the following default credentials :' +
             '\n' +
             '\n  URL      : ' + build_url(port:port, qs:'/') +
             '\n  Username : admin' +
             '\n  Password : password\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Graylog2", build_url(port:port, qs:"/"));
