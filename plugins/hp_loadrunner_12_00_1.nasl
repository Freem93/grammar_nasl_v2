#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77054);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/21 22:04:45 $");

  script_cve_id("CVE-2014-0160");
  script_bugtraq_id(66690);
  script_osvdb_id(105465);
  script_xref(name:"CERT", value:"720951");
  script_xref(name:"EDB-ID", value:"32745");
  script_xref(name:"EDB-ID", value:"32764");
  script_xref(name:"EDB-ID", value:"32791");
  script_xref(name:"EDB-ID", value:"32998");
  script_xref(name:"HP", value:"HPSBMU03040");
  script_xref(name:"HP", value:"SSRT101565");

  script_name(english:"HP LoadRunner 11.52.x < 11.52 Patch 2 / 12.00.x < 12.00 Patch 1 Heartbeat Information Disclosure (Heartbleed)");
  script_summary(english:"Checks the version of HP LoadRunner.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP LoadRunner installed on the remote host is 11.52.x
prior to 11.52 Patch 2 or 12.00.x prior to 12.00 Patch 1. It is,
therefore, affected by an out-of-bounds read error, known as the
'Heartbleed Bug' in the included OpenSSL version.

This error is related to handling TLS heartbeat extensions that could
allow an attacker to obtain sensitive information such as primary key
material, secondary key material, and other protected content.");
  # https://h20565.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c04286049
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91244d7b");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532104/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.heartbleed.com");
  script_set_attribute(attribute:"see_also", value:"https://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/vulnerabilities.html#2014-0160");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140407.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to HP LoadRunner 11.52 Patch 2 / 12.00 Patch 1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:loadrunner");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_loadrunner_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/HP LoadRunner");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include("install_func.inc");

app_name = "HP LoadRunner";
cutoff  = NULL;
cutoff2 = NULL;
fixed   = NULL;
report  = NULL;

# Only 1 install of the server is possible.
install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
path = install['path'];
verui = install['display_version'];

# Determine cutoff if affected branch.
# 11.52.0 is 11.52.1323.0 or 11.52.1517.0
# 12.00.0 is 12.00.661.0
if (version =~ "^11\.52($|[^0-9])")
{
  cutoff  = "11.52.1323.0";
  cutoff2 = "11.52.1517.0";
}
if (version =~ "^12\.00?($|[^0-9])")
{
  cutoff = "12.0.661.0";
  cutoff2 = "12.0.661.0";
}

if (isnull(cutoff)) audit(AUDIT_NOT_INST, app_name + " 11.52.x / 12.0.x");

if (version >= cutoff && version <= cutoff2)
{
  foreach file (make_list("ssleay32_101_x32.dll", "ssleay32_101_x64.dll"))
  {
    dll_path = path + "bin\" + file;
    res = hotfix_get_fversion(path:dll_path);
    err_res = hotfix_handle_error(
      error_code   : res['error'],
      file         : dll_path,
      appname      : app_name,
      exit_on_fail : FALSE
    );
    if (err_res) continue;

    dll_ver = join(sep:'.', res['value']);
    break;
  }
  hotfix_check_fversion_end();

  if (empty_or_null(dll_ver))
    audit(
      AUDIT_VER_FAIL,
      "ssleay32_101_x32.dll and ssleay32_101_x64.dll under " + path + "bin\"
    );

  fixed_dll_ver = '1.0.1.4';
  if (ver_compare(ver:dll_ver, fix:fixed_dll_ver, strict:FALSE) == -1)
    report =
      '\n  Path                  : ' + dll_path +
      '\n  Installed DLL version : ' + dll_ver  +
      '\n  Fixed DLL version     : ' + fixed_dll_ver +
      '\n';
}
# If not at a patchable version, use ver_compare() and suggest
# upgrade if needed; do not use cutoff2 - this will lead to
# false positives.
else if (
  (
    cutoff =~ "^11\." &&
    ver_compare(ver:"11.52", fix:version, strict:FALSE) >= 0 &&
    ver_compare(ver:version, fix:cutoff, strict:FALSE) == -1
  )
  ||
  (
    cutoff =~ "^12\." &&
    ver_compare(ver:"12.00", fix:version, strict:FALSE) >= 0 &&
    ver_compare(ver:version, fix:cutoff, strict:FALSE) == -1
  )
)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 11.52.1323.0 (11.52 Patch 2) / 12.0.661.0 (12.00 Patch 1)' +
    '\n';
}

if (isnull(report)) audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

port = kb_smb_transport();

if (report_verbosity > 0) security_hole(extra:report, port:port);
else security_hole(port);
