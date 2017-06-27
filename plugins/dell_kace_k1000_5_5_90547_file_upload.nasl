#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73213);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_name(english:"Dell KACE K1000 < 5.5.90547 / 5.4.76849 Arbitrary File Upload and Command Execution");
  script_summary(english:"Checks version of Dell KACE K1000");

  script_set_attribute(attribute:"synopsis", value:
"The web interface for a system management appliance is affected by an
arbitrary file upload vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web interface for the version of the Dell KACE K1000 appliance on
the remote host is affected by an arbitrary file upload vulnerability.

With a specially crafted HTTP request, an attacker could upload a
malicious script to the web server directory and use it to execute
arbitrary commands with admin privileges.");
  # http://www.kace.com/support/resources/kb/solutiondetail?sol=SOL121792
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7b00cd52");
  script_set_attribute(attribute:"solution", value:"Upgrade K1000 to 5.5.90547 / 5.4.76849 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:dell:kace_k1000_systems_management_appliance");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("dell_kace_k1000_web_detect.nbin");
  script_require_keys("www/dell_kace_k1000", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

product = "Dell KACE K1000";

port = get_http_port(default:80);

install = get_install_from_kb(
  appname      : "dell_kace_k1000",
  port         : port,
  exit_on_fail : TRUE
);

dir = install["dir"];
version = install["ver"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, product, install_url);

# The advisory refers to the hotfixes as "unversioned" patches.
# Only upgrades through the UI bump the version up.
if (report_paranoia < 2)  audit(AUDIT_PARANOID);

if (version =~ "^5\.4\.\d+$")
  fixed_version = "5.4.76849";
else if (version =~ "^5\.5\.\d+$")
  fixed_version = "5.5.90547";
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, product, port, version);

if (ver_compare(ver:version, fix:fixed_version) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, product, port, version);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';
}

security_hole(port:port, extra:report);
