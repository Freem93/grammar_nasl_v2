#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(11737);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/22 13:59:29 $");

  script_name(english:"NETGEAR Router Default Password (password) for 'admin' Account");
  script_summary(english:"NETGEAR Router Default Password.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service has a well-known default password.");
  script_set_attribute(attribute:"description", value:
"This NETGEAR Router/Access Point has the default password set for the
web administration console ('admin'/'password'). This console provides
read or write access to the router's configuration. An attacker can
take advantage of this to reconfigure the router and possibly re-route
traffic.");
  script_set_attribute(attribute:"solution", value:
"Configure a strong password for the web administration console.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_publication_date", value:"2003/06/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/h:netgear:wg602");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");

  script_dependencies("netgear_www_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("installed_sw/Netgear WWW");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

appname = "Netgear WWW";
get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80, embedded:TRUE);
install = get_single_install(app_name:appname, port:port);

if (install['auth_type'] == 'www')
{
  # validate the authentication is enabled
  res = http_get_cache(port:port, item:"/", exit_on_fail:TRUE);
  if ("401" >!< res) audit(AUDIT_INST_VER_NOT_VULN, appname);

  res = http_send_recv3(
    method:"GET",
    item: "/",
    port:port,
    add_headers:make_array("Referer", build_url(port: port, qs: "/")),
    username:"admin",
    password:"password",
    exit_on_fail: TRUE);

  if ("200" >!< res[0]) audit(AUDIT_INST_VER_NOT_VULN, appname);
}
else if (install['auth_type'] == 'php')
{
  res = http_send_recv3(  
    method:"GET",
    item: "/login.php?username=admin&password=password",
    port:port,
    add_headers:make_array("Referer", build_url(port: port, qs: "/")),
    exit_on_fail: TRUE);

  if ("200" >!< res[0] || "loginok" >!< res[2]) audit(AUDIT_INST_VER_NOT_VULN, appname);
}
else
{
  exit(1, "The NETGEAR device has an unknown authentication mechanism.");
}

report =
  '\nNessus was able to login to the NETGEAR device with default credentials.';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
