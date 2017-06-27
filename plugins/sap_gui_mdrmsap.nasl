#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40617);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/11/14 19:46:54 $");

  script_cve_id("CVE-2008-4387");
  script_bugtraq_id(32186);
  script_osvdb_id(49721);
  script_xref(name:"CERT", value:"277313");

  script_name(english:"SAP SAPgui MDrmSap ActiveX (mdrmsap.dll) Buffer Overflow");
  script_summary(english:"Checks version of affected ActiveX control"); 

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the 'MDrmSap' ActiveX control included with
SAP GUI version 6.40 for Windows. 

This control is reportedly affected by a buffer overflow involving
instantiation by Internet Explorer. 

If an attacker can trick a user on the affected host into visiting a
specially crafted web page, he may be able to leverage these issues to
execute arbitrary code on the host subject to the user's privileges. 

The existence of this vulnerability is confirmed in mdrmsap.dll version
3.5.1.635.  Previous versions may also be affected.");
  script_set_attribute(attribute:"see_also", value:"http://service.sap.com/sap/support/notes/1142431");
  script_set_attribute(attribute:"solution", value:"Apply the patch for the control as described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sap_gui");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) audit(AUDIT_KB_MISSING, 'SMB/Registry/Enumerated');
if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL, "activex_init");

# Locate the file used by the controls.
clsid = "{B01952B0-AF66-11D1-B10D-0060086F6D97}";

file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, 'activex_get_filename() returned NULL.');
}
if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

version = activex_get_fileversion(clsid:clsid);
if (!version || isnull(version))
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

info = '';
fixed_version = '3.7.0.3';
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info +=
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
  }
}

activex_end();

# Report findings
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
      'Moreover, its kill bit is not set so it is accessible via Internet\n' +
      'Explorer.\n';
  }

  if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
  else security_hole(kb_smb_transport());

  exit(0);
}
else
{
  if (rc == FALSE) audit(AUDIT_INST_VER_NOT_VULN, file, version);
  else if (rc == TRUE) audit(AUDIT_ACTIVEX, version);
  else audit(AUDIT_FN_FAIL, 'activex_check_fileversion');
}
