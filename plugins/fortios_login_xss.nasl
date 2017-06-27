#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90314);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/05 16:04:16 $");

  script_bugtraq_id(84429);
  script_osvdb_id(136049, 136050);

  script_name(english:"Fortinet FortiOS Redirect Parameter Multiple Vulnerabilities");
  script_summary(english:"Attempts to execute XSS attack.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Fortinet FortiOS that is
affected by the following vulnerabilities :

  - An open redirect vulnerability exists due to improper
    validation of user-supplied input before using it in
    redirects. An attacker can exploit this, via a specially
    crafted link, to redirect a victim to an arbitrary
    malicious website. (VulnDB 136049)

  - A cross-site scripting (XSS) vulnerability exists due to
    improper validation of user-supplied input to the
    parameter used to govern redirects. An attacker can
    exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (VulnDB 136050)");
  script_set_attribute(attribute:"see_also", value:"https://fortiguard.com/advisory/fortios-open-redirect-vulnerability");
  script_set_attribute(attribute:"solution", value:"Upgrade to Fortinet FortiOS version 5.0.13 / 5.2.3 / 5.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fortinet:fortios");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("fortinet_version.nbin");
  script_require_keys("Host/Fortigate/model", "Host/Fortigate/version");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "FortiOS";

# Even though this is a remote check, the following
# should still be gathered in detection to verify
# that this is a FortiOS device. The default login
# page does not have enough unique characteristics to
# accomplish this.
version = get_kb_item_or_exit("Host/Fortigate/version");
model = get_kb_item_or_exit("Host/Fortigate/model");

port = get_http_port(default:80);

token = SCRIPT_NAME + unixtime();
xss = "javascript:alert('" + token + "');";

exploit = test_cgi_xss(
  port     : port,
  dirs     : make_list('login'),
  cgi      : '',
  qs       : 'redir=' + urlencode(str:xss),
  pass_str : token,
  pass_re  : 'var'
);

if (!exploit) audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(qs:'/', port:port));
