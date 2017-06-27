#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80481);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2013-0169");
  script_bugtraq_id(57778);
  script_osvdb_id(89848);

  script_name(english:"IBM Tivoli Directory Server < 6.0.0.72 / 6.1.0.55 / 6.2.0.30 / 6.3.0.22 with GSKit < 7.0.4.45 / 8.0.14.27 TLS Side-Channel Timing Information Disclosure");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a library installed that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Directory Server
and a version of IBM Global Security Kit (GSKit) that is affected by
an information disclosure vulnerability. The Transport Layer Security
(TLS) protocol does not properly consider timing side-channel attacks,
which allows remote attackers to conduct distinguishing attacks and
plain-text recovery attacks via statistical analysis of timing data
for crafted packets. This type of exploitation is known as the 'Lucky
Thirteen' attack.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21638270");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.0.0.72-ISS-ITDS
  - 6.1.0.55-ISS-ITDS
  - 6.2.0.30-ISS-ITDS
  - 6.3.0.22-ISS-ITDS

Alternatively, upgrade GSKit to 7.0.4.45 or 8.0.50.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:global_security_kit");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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
if (tds_ver =~ "^6\.0\.")
{
  tds_fix = "6.0.0.72";
  tds_patch = "6.0.0.72-ISS-ITDS";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.45';
}
else if (tds_ver =~ "^6\.1\.")
{
  tds_fix = "6.1.0.55";
  tds_patch = "6.1.0.55-ISS-ITDS";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.45';
}
else if (tds_ver =~ "^6\.2\.")
{
  tds_fix = "6.2.0.30";
  tds_patch = "6.2.0.30-ISS-ITDS";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.45';
}
else if (tds_ver =~ "^6\.3\.0($|[^0-9])")
{
  tds_fix = "6.3.0.22";
  tds_patch = "6.3.0.22-ISS-ITDS";
  gsk_ver_regex = "^8\.";
  gsk_fix = '8.0.14.27 / 8.0.50.4';
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
  if (gsk_ver !~ gsk_ver_regex) continue;

  if (
    (gsk_ver =~ "^8\.0\.50\."
      && ver_compare(ver:gsk_ver, fix:"8.0.50.4", strict:FALSE) == -1) ||
    (gsk_ver =~ "^8\.0\.14\."
      && ver_compare(ver:gsk_ver, fix:"8.0.14.27", strict:FALSE) == -1) ||
    (gsk_ver =~ "^7\.0\."
      && ver_compare(ver:gsk_ver, fix:"7.0.4.45", strict:FALSE) == -1)
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

  security_warning(port:port, extra:report);
}
else security_warning(port);
