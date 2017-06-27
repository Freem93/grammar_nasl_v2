#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79746);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/12/05 22:01:45 $");

  script_cve_id("CVE-2014-8104");
  script_bugtraq_id(71402);

  script_name(english:"OpenVPN 2.x < 2.2.3 / 2.3.6 Control Channel Packet Handling DoS");
  script_summary(english:"Checks the OpenVPN version.");

  script_set_attribute(attribute:"synopsis", value:
"An application on the remote host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of OpenVPN
installed on the remote host is affected by an error related to
'Control Channel Packet' handling and TLS-authenticated clients that
could allow denial of service attacks.");
  # Advisory
  # https://community.openvpn.net/openvpn/wiki/SecurityAnnouncement-97597e732b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5f3c40e7");
  # Changelog
  # https://community.openvpn.net/openvpn/wiki/ChangesInOpenvpn23#OpenVPN2.3.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30efbb49");
  # Very old changelogs
  # https://openvpn.net/index.php/open-source/documentation/change-log/70-20-change-log.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e482bea4");
  script_set_attribute(attribute:"solution", value:"Upgrade to OpenVPN 2.2.3 / 2.3.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openvpn:openvpn");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("openvpn_installed.nbin");
  script_require_keys("installed_sw/OpenVPN");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "OpenVPN";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path    = install['path'];

if (version =~ "^2(\.[23])?$") audit(AUDIT_VER_NOT_GRANULAR, "OpenVPN", version);
if (version !~ "^2\.[0-3][^0-9]") audit(AUDIT_NOT_INST, "OpenVPN 2.0.x - 2.3.x");

# Only check and report < 2.3.x if paranoid scan
if (
  (
    report_paranoia > 1
    &&
    (
      # < 2.x
      version =~ "^[0-1]($|[^0-9])" ||
      # 2.0.x / 2.1.x (including alpha/beta/RC)
      version =~ "^2\.[01]($|[^0-9])" ||
      # 2.2.x < 2.2.3
      version =~ "^2\.2-(alpha|beta|RC)(\d+)?($|[^0-9])" ||
      version =~ "^2\.2\.[0-2]($|[^0-9])"
    )
  )
  ||
  # 2.3.x < 2.3.6
  version =~ "^2\.3\.[0-5]($|[^0-9])"
)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report = '\n  Path              : ' + path +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2.3.6 / 2.2.3' +
             '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "OpenVPN", version, path);
