#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59231);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_bugtraq_id(53184);
  script_osvdb_id(81292);
  script_xref(name:"EDB-ID", value:"18763");

  script_name(english:"Liferay Portal 6.0.5 / 6.0.6 Arbitrary File Download");
  script_summary(english:"Checks the version of Liferay Portal.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application affected by an
arbitrary file download vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the installation of
Liferay Portal hosted on the remote web server is affected by an
arbitrary file download vulnerability.  A remote, authenticated
attacker may be able to download arbitrary files using a
specially crafted WebDAV request. 

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");

  script_set_attribute(attribute:"solution", value:"Upgrade to Liferay Portal 6.1.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"see_also", value:"https://github.com/jelmerk/LPS-24562-proof");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("liferay_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/liferay_portal");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Liferay Portal", url);

# Versions 6.0.5 and 6.0.6 are vulnerable.
fix = "6.1.0";
if (ver !~ "^6\.0\.[56]$") audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
