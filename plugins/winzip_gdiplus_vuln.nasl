#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34335);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/15 16:41:31 $");

  script_bugtraq_id(31485);

  script_name(english:"WinZip 11.x 'gdiplus.dll' Unspecified Vulnerability");
  script_summary(english:"Checks the version of WinZip's gdiplus.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
unspecified vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WinZip installed on the remote host is prior to 11.2
SR-1 (Build 8261). It is, therefore, affected by an unspecified
vulnerability since it is known to ship with an old version of the
Microsoft DLL file 'gdiplus.dll'.

Note that only WinZip versions 11.x on Windows 2000 systems use this
file and are thus affected by this issue.");
  script_set_attribute(attribute:"see_also", value:"http://update.winzip.com/wz112sr1.htm");
  script_set_attribute(attribute:"solution", value:"Upgrade to WinZip 11.2 SR-1 (Build 8261) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:winzip:winzip");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("winzip_installed.nbin", "os_fingerprint.nasl");
  script_require_keys("installed_sw/WinZip", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("install_func.inc");
include("misc_func.inc");

appname = 'WinZip';

install = get_single_install(app_name:appname);
path = install['path'];
verui = install['display_version'];

if (verui !~ "^11\.[0-2] *\([0-9]+\)$") audit(AUDIT_NOT_INST, appname + '11.x');

if (report_paranoia < 2)
{
  os = get_kb_item("Host/OS");
  if (!os || "Microsoft Windows 2000" >!< os) audit(AUDIT_OS_NOT, "Microsoft Windows 2000");
}

registry_init();
dll = hotfix_append_path(path:path, value:'gdiplus.dll');
version = hotfix_get_fversion(path:dll);
hotfix_handle_error(error_code:version['error'], file:dll, appname:appname, exit_on_fail:TRUE);
hotfix_check_fversion_end();

version = join(version['value'], sep:'.');
if (ver_compare(ver:version, fix:'5.1.3102.5581', strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port)) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Product         : WinZip ' + verui +
      '\n  DLL             : ' + dll +
      '\n  DLL version     : ' + version +
      '\n  Fixed version   : 5.1.3102.5581\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, verui, path);
