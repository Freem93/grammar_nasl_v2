#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80334);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/09/24 21:08:40 $");

  script_name(english:"IBM Network Security Protection XGS Default Credentials");
  script_summary(english:"Attempts to login using default credentials.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is running a web application that uses a default set
of credentials.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to login to the remote IBM Network Security Protection
XGS device using a known set of default credentials. This allows a
remote attacker to gain administrative access to the device.");
  script_set_attribute(attribute:"solution", value:"Change the password for the default 'admin account.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:security_network_protection_firmware");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_xgs_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("Host/IBM/XGS/version");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:443);
# Only need the version to confirm the device is there
get_kb_item_or_exit("Host/IBM/XGS/version");

url = build_url(port:port,qs:"/dashboard.json");
res = http_send_recv3(
  port            : port,
  method          : 'GET',
  item            : "/dashboard.json",
  username        : "admin",
  password        : "admin",
  exit_on_fail    : TRUE
);

if (
  '200 OK'           >< res[0] &&
  'partition-widget' >< res[2]
)
{
  set_kb_item(name:"Host/IBM/XGS/default_creds",value:TRUE);
  if (report_verbosity > 0)
  {
    report = '\n' + 'Nessus was able to login using the following credentials :\n' +
             '\n' + '  URL      : ' + url +
             '\n' + '  Username : admin' +
             '\n' + '  Password : admin';
    security_hole(port:port, extra:report+'\n');
  }
  else security_hole(port);
}
else audit(AUDIT_HOST_NOT,"affected");
