#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74090);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/01/14 03:46:11 $");

  script_cve_id("CVE-2014-0913");
  script_bugtraq_id(67297);
  script_osvdb_id(106766);

  script_name(english:"IBM Domino 8.5.3 FP6 / 9.0.1 < 8.5.3 FP6 IF2 / 9.0.1 FP1 iNotes XSS (credentialed check)");
  script_summary(english:"Checks version of ninotes.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of IBM Domino (formerly Lotus Domino)
8.5.3 Fix Pack 6 (FP6) Interim Fix 2 (IF2) or 9.0.1 prior to 9.0.1 Fix
Pack 1 (FP1), and thus is affected by an unspecified error related to
the iNotes component that could allow cross-site (XSS) scripting
attacks.");
  # Advisory
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21671981");
  # Patch
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21663874");
  # Patch
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037141");
  script_set_attribute(attribute:"solution", value:"Upgrade to IBM Domino 8.5.3 FP6 IF2 / 9.0.1 FP1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:inotes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("SMB/Domino/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

appname = "IBM Domino";
kb_base = "SMB/Domino/";

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

if (
  version !~ "^8\.5\.36($|[^0-9])" &&
  version !~ "^9\.0\.10($|[^0-9])"
) audit(AUDIT_NOT_INST, appname + " 8.5.36 / 9.0.10");

dll = "nnotes.dll";
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

if (
  (
    # 8
    dll_version =~ "^8\." &&
    ver_compare(ver:dll_version, fix:'8.5.36.14105', strict:FALSE) < 0
  ) ||
  (
    # 9
    dll_version =~ "^9\." &&
    ver_compare(ver:dll_version, fix:'9.0.11.14093', strict:FALSE) < 0
  )
)
{
  port = kb_smb_transport();
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + temp_path +
      '\n  Installed version : ' + dll_version +
      '\n  Fixed version     : 8.5.36.14105 / 9.0.11.14093' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, dll, dll_version, path);
