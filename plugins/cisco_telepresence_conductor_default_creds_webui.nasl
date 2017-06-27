#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79585);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:12 $");

  script_name(english:"Cisco TelePresence Conductor Default Credentials (Web UI)");
  script_summary(english:"Tries to login with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application uses default credentials.");
  script_set_attribute(attribute:"description", value:
"It is possible to log into the remote Cisco TelePresence Conductor
installation by providing the default credentials. A remote,
unauthenticated attacker can exploit this to gain administrative
control.");
  script_set_attribute(attribute:"solution", value:"Secure any default accounts with a strong password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_conductor");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_conductor_webui_detect.nbin");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("Host/Cisco_TelePresence_Conductor");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

get_kb_item_or_exit("Host/Cisco_TelePresence_Conductor");

port = get_http_port(default:443);

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

user = 'admin';
pass = 'TANDBERG';
url = "/api/external/status/system.php";
full_url = build_url(qs:url, port:port);

res = http_send_recv3(
  method          : "GET",
  item            : url,
  port            : port,
  username        : user,
  password        : pass
);

if ("200 OK" >!< res[0] || '"product_name":"Cisco TelePresence Conductor"' >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Cisco TelePresence Conductor", full_url);

if (report_verbosity > 0)
{
  report =
    '\n' + 'Nessus was able to login using the following credentials:' +
    '\n' +
    '\n' + '  URL      : ' + full_url +
    '\n' + '  Username : ' + user +
    '\n' + '  Password : ' + pass +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
