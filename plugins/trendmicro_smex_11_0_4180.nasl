#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84007);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/23 16:29:32 $");

  script_cve_id("CVE-2015-3326");
  script_bugtraq_id(74661);
  script_osvdb_id(122185);

  script_name(english:"Trend Micro ScanMail for Exchange 10.2 < Build 3318 / 11.x < Build 4180 Predictable Session IDs");
  script_summary(english:"Checks the version of Trend Micro ScanMail.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an email security application installed
with weak session ID generation.");
  script_set_attribute(attribute:"description", value:
"The version of Trend Micro ScanMail for Exchange (SMEX) installed on
the remote Windows host is affected by a flaw in its bundled web-based
user interface due to insufficient complexity in the generation of
session IDs. A remote attacker, by more easily guessing the session
ID, can use an authenticated user's session to gain access to the web
interface.");
  script_set_attribute(attribute:"see_also", value:"http://esupport.trendmicro.com/solution/en-US/1109669.aspx");
  script_set_attribute(attribute:"solution", value:
"Apply 11.0 Hot Fix Build 4180 / 10.2 Hot Fix Build 3318.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trend_micro:scanmail");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("trendmicro_smex_installed.nbin");
  script_require_keys("installed_sw/Trend Micro ScanMail for Exchange");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

appname = 'Trend Micro ScanMail for Exchange';
install = get_single_install(app_name:appname,exit_if_unknown_ver:TRUE);
version = install["version"];
patch   = int(install["Patch Build"]);
spack   = int(install["Service Pack"]);
path    = install["path"];
dllfix  = FALSE;
port    = kb_smb_transport();

if(path !~ "\\$") path += "\";

if(version =~ "^11\.0\.")
  dllfix = "11.0.0.4180";
else if(version =~ "^10\.2\.")
  dllfix = "10.2.0.3318";
else
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

# File Check
dll = path + "servPolicyController.dll";
dllver = hotfix_get_fversion(path:dll);
hotfix_handle_error(
  error_code   : dllver['error'], 
  file         : dll, 
  appname      : appname, 
  exit_on_fail : TRUE
);
dllver = join(dllver['value'], sep:'.');
hotfix_check_fversion_end();

if(ver_compare(ver:dllver,fix:dllfix,strict:FALSE) < 0)
{
  if(report_verbosity > 0)
  {
    report =
      '\n  File              : ' + dll +
      '\n  Installed version : ' + dllver +
      '\n  Fixed version     : ' + dllfix + '\n';
    security_warning(port:port, extra:report);
  } else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
