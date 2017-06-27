#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61463);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_bugtraq_id(54146);
  script_osvdb_id(83087);

  script_name(english:"AOL dnUpdater ActiveX dnu.exe Init() Method Remote Code Execution");
  script_summary(english:"Checks the version of an ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control that is affected by a remote
code execution vulnerability. "
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has an install of the AOL dnUpdater ActiveX control
(dnu.exe) prior to version 1.1.25.1.  As such, it reportedly does not
properly verify the function pointer passed by the 'pData' argument of
the control's 'Init()' method.

A remote attacker could exploit this vulnerability by tricking a user
into opening a specially crafted page that could execute arbitrary
code subject to the user's privileges.

Note that this control reportedly is included with America Online's
Toolbar, Desktop, and IM as well as Winamp."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-098/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jun/140");
  script_set_attribute(
    attribute:"solution",
    value:
"Disable/remove the control or see the ZDI advisory for update
instructions."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init()');

# Determine if the control is installed.
clsid = '{7B089B94-D1DC-4C6B-87E1-8156E22C1D96}';
fixed_version = "1.1.25.1";

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

# And check it.
info = '';
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class identifier  : ' + clsid +
            '\n  Filename          : ' + file +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

activex_end();

# Report findings.
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

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version+".");
  else if (rc == TRUE) audit(AUDIT_ACTIVEX, version);
  else audit(AUDIT_FN_FAIL, 'activex_check_fileversion()');
}
