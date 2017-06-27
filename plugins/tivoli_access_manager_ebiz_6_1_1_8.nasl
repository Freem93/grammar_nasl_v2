#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80480);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/07/18 14:06:55 $");

  script_cve_id("CVE-2013-6329");
  script_bugtraq_id(64249);
  script_osvdb_id(100864);

  script_name(english:"IBM Tivoli Access Manager for e-Business < 6.0.0.31 / 6.1.0.12 / 6.1.1.8 or GSKit < 7.0.4.47 SSL/TLS Handshake Processing DoS");
  script_summary(english:"Checks the Runtime component and GSKit version.");

  script_set_attribute(attribute:"synopsis", value:
"An access and authorization control management system installed on the
remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the install of the IBM Tivoli
Access Manager for e-Business is affected by a denial of service
vulnerability due to an issue when processing SSL/TLS handshakes when
SSLv2 is used with session resumption. An attacker can exploit this
vulnerability by sending a specially crafted SSL request to cause an
application crash or hang.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21659837");
  script_set_attribute(attribute:"solution", value:
"Apply the interim fix 6.0.0-ISS-TAM-IF0031 / 6.1.0-TIV-TAM-IF0012 /
6.1.1-ISS-TAM-IF0008 or later. Alternatively, upgrade GSKit to
7.0.4.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ibm_gskit_installed_nix.nbin", "tivoli_access_manager_ebiz_installed_components_cred.nasl");
  script_require_keys("installed_sw/IBM GSKit", "installed_sw/IBM Access Manager for e-Business / IBM Security Access Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

tam_app = 'IBM Access Manager for e-Business / IBM Security Access Manager';
install = get_single_install(app_name:tam_app, exit_if_unknown_ver:TRUE);

tam_ver   = install['version'];
tam_path  = install['path'];
tam_fix   = NULL;
tam_patch = NULL;

# Affected :
# 6.0.0.x < 6.0.0.31
# 6.1.0.x < 6.1.0.12
# 6.1.1.x < 6.1.1.8
if (tam_ver =~ "^6\.0\.0\.")
{
  tam_fix   = "6.0.0.31";
  tam_patch = "6.0.0-ISS-TAM-IF0031";
}
else if (tam_ver =~ "^6\.1\.0\.")
{
  tam_fix   = "6.1.0.12";
  tam_patch = "6.1.0-TIV-TAM-IF0012";
}
else if (tam_ver =~ "^6\.1\.1\.")
{
  tam_fix   = "6.1.1.8";
  tam_patch = "6.1.1-ISS-TAM-IF0008";
}

if (isnull(tam_fix) || ver_compare(ver:tam_ver, fix:tam_fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, tam_app, tam_ver, tam_path);

# Check GSKit version if TAM is not patched
gsk_app = "IBM GSKit";
gsk_fix  = "7.0.4.47";

# We don't bother to exit if we can't detect any GSKit installations
gsk_installs = get_installs(app_name:gsk_app);
gsk_report   = NULL;
gsk_vuln     = 0;

foreach gsk_install (gsk_installs[1])
{
  gsk_ver  = gsk_install['version'];
  gsk_path = gsk_install['path'];

  if (gsk_ver =~ "^7\.0\." &&
    ver_compare(ver:gsk_ver, fix:gsk_fix, strict:FALSE) == -1)
  {
    gsk_report +=
      '\n  Path                    : ' + gsk_path +
      '\n  Installed GSKit Version : ' + gsk_ver  +
      '\n  Fixed GSKit Version     : ' + gsk_fix  +
      '\n';

    gsk_vuln++;
  }
}

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\n' + 'The install of ' + tam_app + ' is vulnerable :' +
    '\n' +
    '\n' + '  Path              : ' + tam_path +
    '\n' + '  Installed version : ' + tam_ver  +
    '\n' + '  Fixed version     : ' + tam_fix  +
    '\n' +
    '\n' + 'Install ' + tam_patch  + ' to update installation.' +
    '\n';

  if (!isnull(gsk_report))
  {
    instance = " instance "; is_are   = " is ";

    if (gsk_vuln > 1) {instance = " instances "; is_are = " are ";}

    report +=
      '\nAlso, the following vulnerable'+instance+'of '+gsk_app+is_are+'installed on the'+
      '\nremote host :' +
      '\n' +
      gsk_report;
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
