#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80482);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:47:37 $");

  script_cve_id("CVE-2014-0963");
  script_bugtraq_id(67238);
  script_osvdb_id(106786);

  script_name(english:"IBM Security Directory Server < 6.1.0.61 / 6.2.0.36 / 6.3.0.30 / 6.3.1.2 with GSKit < 7.0.4.50 / 8.0.50.20 SSL CPU Utilization DoS");
  script_summary(english:"Checks the version of Security Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Security Directory Server and GSKit is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Security Directory Server
(formerly IBM Tivoli Directory Server) and a version of IBM Global
Security Kit (GSKit) that is affected by a denial of service
vulnerability due to a flaw in the GSKit library. An attacker can
exploit this issue via a specially-crafted SSL to use excessive CPU
resources resulting in the host to become unresponsive.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21672724");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.61-ISS-ITDS
  - 6.2.0.36-ISS-ITDS
  - 6.3.0.30-ISS-ITDS
  - 6.3.1.2-ISS-ISDS

Alternatively, upgrade GSKit to 7.0.4.50 or 8.0.50.20.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:security_directory_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("ibm_gskit_installed.nasl", "tivoli_directory_svr_installed.nasl");
  script_require_keys("installed_sw/IBM GSKit", "installed_sw/IBM Security Directory Server");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

tds_name = "IBM Security Directory Server";
tds_install = get_single_install(app_name:tds_name, exit_if_unknown_ver:TRUE);

tds_ver  = tds_install['version'];
tds_path = tds_install['path'];

tds_fix       = NULL;
tds_patch     = NULL;
gsk_ver_regex = NULL;
gsk_fix       = NULL;

# Ensure that TDS version is affected.
if (tds_ver =~ "^6\.1\.")
{
  tds_fix = "6.1.0.61";
  tds_patch = "6.1.0.61-ISS-ITDS";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.50';
}
else if (tds_ver =~ "^6\.2\.")
{
  tds_fix = "6.2.0.36";
  tds_patch = "6.2.0.36-ISS-ITDS";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.50';
}
else if (tds_ver =~ "^6\.3\.0($|[^0-9])")
{
  tds_fix = "6.3.0.30";
  tds_patch = "6.3.0.30-ISS-ITDS";
  gsk_ver_regex = "^8\.";
  gsk_fix = '8.0.50.20';
}
else if (tds_ver =~ "^6\.3\.1($|[^0-9])")
{
  tds_fix = "6.3.1.2";
  tds_patch = "6.3.1.2-ISS-ISDS";
  gsk_ver_regex = "^8\.";
  gsk_fix = '8.0.50.20';
}

# If the IF has been installed or the branch is not affected, exit.
if (isnull(tds_fix) || ver_compare(ver:tds_ver, fix:tds_fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_PATH_NOT_VULN, tds_name, tds_ver, tds_path);

# If we got this far, we need to look at GSKit.
gsk_app = "IBM GSKit";

# We don't bother to exit if we can't detect any GSKit installations
gsk_installs = get_installs(app_name:gsk_app);
gsk_report   = NULL;
gsk_vuln     = 0;

foreach gsk_install (gsk_installs[1])
{
  gsk_ver  = gsk_install['version'];
  gsk_path = gsk_install['path'];

  # There can only be a single install per major version. So we will
  # have at most one vulnerable install.
  if (gsk_ver !~ gsk_ver_regex)
    audit(AUDIT_INST_PATH_NOT_VULN, gsk_app, gsk_ver, gsk_path);

  if (
    (gsk_ver =~ "^8\.0\.50\."
      && ver_compare(ver:gsk_ver, fix:gsk_fix, strict:FALSE) == -1) ||
    (gsk_ver =~ "^7\.0\."
      && ver_compare(ver:gsk_ver, fix:gsk_fix, strict:FALSE) == -1)
  )
  {
    gsk_report +=
      '\n  Path                    : ' + gsk_path +
      '\n  Installed GSKit Version : ' + gsk_ver  +
      '\n  Fixed GSKit Version     : ' + gsk_fix  +
      '\n';

    gsk_vuln++;
  }
}

port = get_kb_item('SMB/transport');
if (!port) port = 445;

if (report_verbosity > 0)
{
  report =
    '\nThe install of ' + tds_name + ' is vulnerable :' +
    '\n' +
    '\n  Path              : ' + tds_path +
    '\n  Installed version : ' + tds_ver  +
    '\n  Fixed version     : ' + tds_fix  +
    '\n' +
    '\nInstall ' + tds_patch  + ' to update installation.' +
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
