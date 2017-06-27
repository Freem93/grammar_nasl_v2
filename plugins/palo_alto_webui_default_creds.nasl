#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71496);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/10 18:05:23 $");

  script_osvdb_id(129836);

  script_name(english:"Palo Alto Networks PAN-OS Firewall/Panorama WebUI Default Credentials");
  script_summary(english:"Attempts to login with the default username/password.");

  script_set_attribute(attribute:"synopsis", value:
"A web application on the remote host is protected using default
credentials.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS Firewall / Panorama WebUI interface on
the remote host has the 'admin' user account secured with the default
password. An unauthenticated, remote attacker can exploit this to gain
administrative access to the web interface.");
  # https://live.paloaltonetworks.com/t5/Management-Articles/What-is-the-Default-Login-Credential/ta-p/56871
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?428c8b63");
  script_set_attribute(attribute:"solution", value:"Secure the 'admin' user account with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("palo_alto_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/palo_alto_panos");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

get_kb_item_or_exit("www/palo_alto_panos");

port = get_http_port(default:443, embedded:TRUE);

install = get_install_from_kb(appname:"palo_alto_panos", port:port, exit_on_fail:FALSE);
if (isnull(install)) audit(AUDIT_NOT_INST, "Palo Alto Firewall / Panorama");
app = "PAN-OS";

model = get_kb_item("palo_alto/platform/model");
if (model)
  app = model;

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

url = install['dir'] + '/php/login.php';
full_url = build_url(qs:url, port:port);

user = 'admin';
pass = 'admin';

postdata =
  'prot=https%3A&server=' +
  '&authType=init' +
  '&challengeCookie=' +
  '&user=' + user +
  '&passwd=' + pass +
  '&challengePwd=' +
  '&ok=Login';

res = http_send_recv3(
  method:'POST',
  item:url,
  port:port,
  content_type:'application/x-www-form-urlencoded',
  data:postdata,
  follow_redirect:1,
  exit_on_fail:TRUE
);

if (
  'Invalid username or password' >< res[2] ||
  'Your device is still configured with the default admin account credentials.' >!< res[2]
) audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Palo Alto ' + app, full_url);

report =
  '\n' + 'Nessus was able to log into the Palo Alto ' + app + ' WebUI using' +
  '\n' + 'the following information :' +
  '\n' +
  '\n  URL      : ' + full_url +
  '\n  Username : ' + user +
  '\n  Password : ' + pass + '\n';
security_report_v4(
  port       : port,
  severity   : SECURITY_HOLE,
  extra      : report
);
