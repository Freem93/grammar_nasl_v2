#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73185);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_name(english:"McAfee Cloud Single Sign On WebUI Default Credentials");
  script_summary(english:"Tries to login with the default credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is protected using default
credentials.");
  script_set_attribute(attribute:"description", value:
"The McAfee Cloud Single Sign On WebUI interface on the remote host
has the 'admin' user account secured with the default password. A
remote, unauthenticated attacker could exploit this to gain
administrative access to the web interface.");
  # https://kb.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/24000/PD24575/en_US/mcsso_401_pg_a00_en-us.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31058924");
  script_set_attribute(attribute:"solution", value:"Secure the 'admin' user account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:cloud_single_sign_on");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:cloud_identity_manager");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("mcafee_csso_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/mcafee_csso");
  script_require_ports("Services/www", 8443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/mcafee_csso");
port = get_http_port(default:8443);

app_name = get_kb_item_or_exit("www/" + port + "/mcafee_csso/Name");
kb_appname = "mcsso_ui";
install = get_install_from_kb(appname:kb_appname, port:port, exit_on_fail:FALSE);

if (isnull(install)) audit(AUDIT_NOT_INST, app_name);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/j_security_check';
full_url = build_url(qs:url, port:port);

user = 'admin';
pass = 'passwd';

postdata =
  'j_username='+user+
  '&j_password='+pass;

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:1,
  exit_on_fail:TRUE
);

if ("The credentials you entered are incorrect" >< res[2] || "splat.jsp" >!< res[1])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, full_url);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to log into the ' + app_name + ' using' +
    '\n' + 'the following information :' +
    '\n' +
    '\n  URL      : ' + full_url +
    '\n  Username : ' + user +
    '\n  Password : ' + pass + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
