#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74224);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/05/29 01:42:49 $");

  script_cve_id("CVE-2013-4068");
  script_bugtraq_id(62481);
  script_osvdb_id(97453);

  script_name(english:"IBM Domino 8.5.3 < 8.5.3 Fix Pack 5 Interim Fix 1 iNotes Buffer Overflow (credentialed check)");
  script_summary(english:"Checks version of ninotes.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected a buffer
overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Domino (formerly Lotus Domino)
8.5.3 prior to 8.5.3 Fix Pack 5 (FP5) Interim Fix 1 (IF1), and thus is
affected by a buffer overflow error in the iNotes component that could
allow an authenticated user to execute arbitrary code.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21649476");
  # Patch
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21650146");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 8.5.3 FP5 IF1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:inotes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("SMB/Domino/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

appname = "IBM Domino";
kb_base = "SMB/Domino/";

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

if (version !~ "^8\.5\.3\d($|[^0-9])") audit(AUDIT_NOT_INST, appname + " 8.5.3.x");

dll = "ninotes.dll";
temp_path = path + "\" + dll;

dll_ver = hotfix_get_fversion(path:temp_path);
err_res = hotfix_handle_error(
  error_code   : dll_ver['error'],
  file         : temp_path,
  appname      : appname,
  exit_on_fail : TRUE
);
hotfix_check_fversion_end();

dll_version = join(dll_ver['value'], sep:".");

if (ver_compare(ver:dll_version, fix:'8.5.35.13251', strict:FALSE) < 0)
{
  port = kb_smb_transport();
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + temp_path +
      '\n  Installed version : ' + dll_version +
      '\n  Fixed version     : 8.5.35.13251' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, dll, dll_version, path);
