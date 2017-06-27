#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(85448);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/08/18 14:49:03 $");

  script_osvdb_id(124449, 124450, 124451);

  script_name(english:"Evernote < 5.8.1 ActiveX Control Arbitrary File Overwrite");
  script_summary(english:"Checks if the kill bit is set.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control installed that is
affected by a file overwrite vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Evernote installed on the remote Windows host is prior
to 5.8.1. It is, therefore, affected by an arbitrary file overwrite
vulnerability in the EvernoteIE.dll ActiveX control due to using the
writeFileContent(), LoadFile(), and ReadFileContent() methods in an
insecure manner. A remote, unauthenticated attacker can exploit this
by tricking a user into opening a specially crafted web page, allowing
the attacker to read and overwrite arbitrary files.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Evernote 5.8.1 or later. Alternatively, disable the ActiveX
control.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"https://discussion.evernote.com/topic/79359-evernote-for-windows-581/");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:evernote:evernote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "evernote_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Evernote");
  script_require_ports(139, 445);

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_activex_func.inc');
include('misc_func.inc');
include('global_settings.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app = 'Evernote';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
version = install['version'];

# 5.8.1.6061 is the first fixed release.
if(ver_compare(ver:version, fix:'5.8.1.6061', strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app, version);

if (activex_init() != ACX_OK)
  audit(AUDIT_FN_FAIL, 'activex_init()');

clsid = '{92EF2EAD-A7CE-4424-B0DB-499CF856608E}';

# Make sure the control is installed
file = activex_get_filename(clsid:clsid);
if (empty_or_null(file))
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

info = "";
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info +=
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 5.8.1\n';
}
activex_end();

report = "";
if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0)
    security_hole(port:kb_smb_transport(), extra:report);
  else
    security_hole(kb_smb_transport());

  exit(0);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app, version);
