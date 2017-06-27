#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(58603);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/02/03 20:48:27 $");

  script_name(english:"at32 Reverse Proxy Admin Portal No Password ");
  script_summary(english:"Detects if password is configured for admin portal");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is running a reverse proxy server with an unprotected
admin portal requiring no login password."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The admin console for the at32 Reverse Proxy software does not
require a login password.  This can allow a remote attacker to change
the reverse proxy rules without having to authenticate."
  );
  script_set_attribute(attribute:"solution", value:"Set a login password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:at32:reverse_proxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("at32_reverse_proxy_detect.nasl");
  script_require_ports("Services/www", 8082);
  script_require_keys("www/at32_reverse_proxy");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8082);

install = get_install_from_kb(appname:'at32_reverse_proxy', port:port, exit_on_fail:TRUE);

url = install['dir'] + "/";
res = http_get_cache(item:url, port:port, exit_on_fail:TRUE);

if ("<B>Note:</B> You do not have a password setup for admin." >< res)
{
  if (report_verbosity > 0)
  {
    report = '\n  URL : ' + build_url(qs:url, port:port) +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The at32 reverse proxy admin portal on port " + port + " is not affected.");
