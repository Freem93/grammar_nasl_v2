#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45043);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(38544);
  script_xref(name:"OSVDB", value:"62735");
  script_xref(name:"Secunia", value:"38844");

  script_name(english:"CSS Web Installer CSSWEBLib.Installer ActiveX InstallProduct1 Method Overflow");
  script_summary(english:"Checks for the control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is prone to a
buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The CSS Web Installer ActiveX control, a component of the Authentium
Command On Demand virus scanner, installed on the remote Windows host
reportedly is affected by a buffer overflow involving the
'InstallProduct1' method, and possibly the 'InstallProduct' and
'InstallProduct2' methods as well. 

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary code on the affected system subject to the user's
privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://sotiriu.de/adv/NSOADV-2010-006.txt"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2010/Mar/104"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Remove or disable the control as the product is no longer supported."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


clsids = make_list(
  '{6CCE3920-3183-4B3D-808A-B12EB769DE12}',
  '{C81B5180-AFD1-41A3-97E1-99E8D254DB98}'
);


# Determine if any of the controls are installed.
info = '';
installs = 0;

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);
  if (isnull(file))
  {
    activex_end();
    exit(1, "activex_get_filename() returned NULL.");
  }
  if (!file) continue;

  installs++;

  # Get its version.
  version = activex_get_fileversion(clsid:clsid);
  if (!version) version = "unknown";

  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file + 
            '\n  Installed version : ' + version + '\n';

    if (!thorough_tests) break;
  }
}
activex_end();


# Report findings.
if (installs)
{
  if (info)
  {
    if (report_paranoia > 1)
    {
      if (installs == 1) s = " was";
      else s = "s were";

      report = info +
        '\n' +
        'Note, though, that Nessus did not check whether the kill bit' + s + '\n' +
        "set for the control's CLSID because of the Report Paranoia setting" + '\n' +
        'in effect when this scan was run.\n';
    }
    else
    {
      if (installs == 1) s = "its kill bit is not set so it is";
      else s = "their kill bits are not set so they are";

      report = info +
        '\n' +
        'Moreover, ' + s + ' accessible via Internet\n' +
        'Explorer.\n';
    }

    if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
    exit(0);
  }
  else
  {
    if (installs == 1) exit(0, "The control is installed but its kill bit is set.");
    else exit(0, installs+" instances of the control are installed but their kill bits are set.");
  }
}
else exit(0, "The control is not installed.");
