#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63280);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/16 11:01:00 $");

  script_bugtraq_id(56678);
  script_osvdb_id(87881);

  script_name(english:"WibuKey Runtime ActiveX Control DisplayMessageDialog Method String Parsing Overflow");
  script_summary(english:"Checks version of ActiveX Control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to the version of the WibuKey Runtime ActiveX control
installed on the remote host, the DisplayMessageDialog() method within
WkWin32.dll is affected by a stack-based buffer overflow vulnerability. 
By tricking a user into opening a specially crafted web page, an
attacker may be able to execute arbitrary code."
  );
  # http://www.protekresearchlab.com/index.php?option=com_content&view=article&id=68&Itemid=68
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec750c9a");
  script_set_attribute(attribute:"solution", value:"Upgrade to WibuKey 6.10 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-13-520");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:wibu:wibukey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

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

# Locate files used by the control.
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, 'activex_init');

info = "";

clsid = "{00010000-0000-1011-8002-0000C06B5161}";
fix = "6.10.1003.500";

file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:fix) == TRUE)
  {
    if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
    {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file + 
              '\n  Installed version : ' + ver + 
              '\n  Fixed version     : ' + fix + '\n';
    }
  }
}
else
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

activex_end();

if (info)
{
  if (report_paranoia > 1)
  {
    report = info +
      '\n' +
      'Note, though, that Nessus did not check whether the kill bit was\n' +
      'set for the control\'s CLSID because of the Report Paranoia setting\n' +
      'in effect when this scan was run.\n';
  }
  else
  {
    report = info +
      '\n' +
      'Additionally, the kill bit is not set for this ActiveX control,\n' +
      'making it accessible via Internet Explorer.\n';
  }
  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());
}
else
{
  if(ver_compare(ver:ver, fix:fix, strict:FALSE) == -1)
    audit(AUDIT_ACTIVEX, ver);  
  else
    audit(AUDIT_INST_VER_NOT_VULN, file, ver);
}
