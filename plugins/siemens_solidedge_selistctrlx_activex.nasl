#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66839);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/19 18:02:18 $");

  script_bugtraq_id(60161);
  script_osvdb_id(93696);
  script_xref(name:"EDB-ID", value:"25712");

  script_name(english:"Siemens Solid Edge SEListCtrlX ActiveX Control SetItemReadOnly Method Memory Address Write Arbitrary Code Execution");
  script_summary(english:"Checks if kill bit is set for ActiveX control");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an ActiveX control that is affected by a code
execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host has the Siemens Solid Edge SEListCtrlX ActiveX control
installed.  This control has a flaw that could allow an attacker to
execute arbitrary code via the 'SetItemReadOnly()' method by tricking a
user into opening a specially crafted web page."
  );
  script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/9sg_siemens_adv_ii.htm");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/240797");
  script_set_attribute(attribute:"solution", value:"Disable the SEListCtrlX ActiveX control.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Siemens Solid Edge ST4 SEListCtrlX ActiveX Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:siemens:solid_edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

clsid = '{5D6A72E6-C12F-4C72-ABF3-32F6B70EBB0D}';

if (activex_init() != ACX_OK) audit(AUDIT_FN_FAIL,'activex_init');

info = '';

vuln_version = '105.0.0.102';

file = activex_get_filename(clsid:clsid);

if (isnull(file))
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_filename');
}

if (!file)
{
  activex_end();
  audit(AUDIT_ACTIVEX_NOT_FOUND, clsid);
}

# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (isnull(version))
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_fileversion');
}
if (version == "")
{
  activex_end();
  audit(AUDIT_VER_FAIL, file);
}

killbit = activex_get_killbit(clsid:clsid);

if (killbit == -1)
{
  activex_end();
  audit(AUDIT_FN_FAIL, 'activex_get_killbit', -1);
}

if (ver_compare(ver:version, fix:vuln_version) <= 0)
{
  if (report_paranoia > 1 || killbit == 0)
  {
      info += '\n  Class identifier  : ' + clsid +
              '\n  Filename          : ' + file +
              '\n  Installed version : ' + version;
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
  if (ver_compare(ver:version, fix:vuln_version) > 0)
    audit(AUDIT_INST_VER_NOT_VULN, 'SIEMENS Solid Edge SEListCtrlX ActiveX', version);
  else
    audit(AUDIT_ACTIVEX, version);
}
