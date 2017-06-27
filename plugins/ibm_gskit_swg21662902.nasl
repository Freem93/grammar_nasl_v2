#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72220);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/14 15:43:28 $");

  script_cve_id("CVE-2013-6747");
  script_bugtraq_id(65156);
  script_osvdb_id(102556);

  script_name(english:"IBM Tivoli Directory Server < 6.1.0.59 / 6.2.0.34 / 6.3.0.26 with GSKit < 7.0.4.48 / 8.0.50.16 X.509 Certificate Chain DoS");
  script_summary(english:"Checks the version of Tivoli Directory Server.");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Tivoli Directory Server and GSKit is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Directory Server
6.1.0.x prior to 6.1.0.59, 6.2.0 prior to 6.2.0.34, or 6.3.0.x prior
to 6.3.0.26, and a version of IBM Global Security Kit (GSKit) 7.0.x
prior to 7.0.4.48 or 8.0.50.x prior to 8.0.50.16. It is, therefore,
affected by a denial of service vulnerability due to a flaw in the
GSKit library. An attacker can exploit this vulnerability via a
malformed X.509 certificate chain to cause an application crash or
hang.");
  # https://www-304.ibm.com/support/docview.wss?uid=swg21662902
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1afae799");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_gskit_certificate_chain_vulnerability_in_ibm_security_directory_server_and_tivoli_directory_server_cve_2013_6747?lang=en_us
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?9c119340");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate fix based on the vendor's advisory :

  - 6.1.0.59-ISS-ITDFS-IF0059
  - 6.2.0.34-ISS-ITDFS-IF0034
  - 6.3.0.26-ISS-ITDFS-IF0026

Alternatively, upgrade GSKit to 7.0.4.48 or 8.0.50.16.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

tds_fix   = NULL;
tds_patch = NULL;
gsk_ver_regex = NULL;
gsk_fix = NULL;

# Ensure that TDS version is affected.
if (tds_ver =~ "^6\.1\.")
{
  tds_fix = "6.1.0.59";
  tds_patch = "6.1.0.59-ISS-ITDFS-IF0059";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.48';
}
else if (tds_ver =~ "^6\.2\.")
{
  tds_fix = "6.2.0.34";
  tds_patch = "6.2.0.34-ISS-ITDFS-IF0034";
  gsk_ver_regex = "^7\.";
  gsk_fix = '7.0.4.48';
}
else if (tds_ver =~ "^6\.3\.")
{
  tds_fix = "6.3.0.26";
  tds_patch = "6.3.0.26-ISS-ITDFS-IF0026";
  gsk_ver_regex = "^8\.";
  gsk_fix = '8.0.50.16';
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
    '\n' + 'The install of ' + tds_name + ' is vulnerable :' +
    '\n' +
    '\n' + '  Path              : ' + tds_path +
    '\n' + '  Installed version : ' + tds_ver  +
    '\n' + '  Fixed version     : ' + tds_fix  +
    '\n' +
    '\n' + 'Install ' + tds_patch  + ' to update installation.' +
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
