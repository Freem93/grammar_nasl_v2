#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73372);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_name(english:"EMC Cloud Tiering Appliance User Interface Default Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(attribute:"synopsis", value:
"The remote web service is protected using a default set of known
credentials.");
  script_set_attribute(attribute:"description", value:
"The remote EMC Cloud Tiering Appliance user interface uses a known set
of default credentials. Knowing these, an attacker with access to the
service can gain administrative access to the device.");
  script_set_attribute(attribute:"solution", value:"Change the default admin login credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:emc:cloud_tiering_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:emc:cloud_tiering_appliance_virtual_edition");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("emc_cta_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/emc_cta_ui");
  script_require_ports("Services/www", 443);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/emc_cta_ui");

app_name = "EMC Cloud Tiering Appliance";
port = get_http_port(default:443);
install = get_install_from_kb(appname:'emc_cta_ui', port:port, exit_on_fail:TRUE);

dir = install['dir'];
report_url = build_url(port:port, qs:dir);
url = "/api/login";

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

# Creds are root/rain but the API requires the password be sent as
# comma-separated ascii ordinal values.
username = 'root';
password = '114,97,105,110';
password_display = 'rain';

postdata =
  '<Request>
  <Username>' + username + '</Username>
  <Password>' + password + '</Password>
  </Request>';

res = http_send_recv3(
  method:'POST',
  item:url,
  data:postdata,
  content_type:'text/xml',
  port:port,
  exit_on_fail:TRUE
  );

if ("<Code>0</Code>" >< res[2] && "Login Failed" >!< res[2])
{
  if (report_verbosity > 0)
  {
    header = 'Nessus was able to gain access using the following URL';
    trailer =
      'and the following set of credentials :' +
      '\n' +
      '\n' + '  User name : ' + username +
      '\n' + '  Password  : ' + password_display;

    report = get_vuln_report(
      items   : url,
      port    : port,
      header  : header,
      trailer : trailer
    );

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, report_url);
