
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58389);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/23 20:42:24 $");

  script_cve_id("CVE-2012-0198");
  script_bugtraq_id(52252);
  script_osvdb_id(79735);
  script_xref(name:"EDB-ID", value:"18727");

  script_name(english:"IBM Tivoli Provisioning Manager Express for Software Distribution Isig.isigCtl.1 ActiveX RunAndUploadFile Method Boundary Error Remote Overflow");
  script_summary(english:"Checks if the kill bit is set");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control installed that is
affected by a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has the IBM Tivoli Provisioning Manager Express for
Software Distribution Isig.isigCtl.1 ActiveX control installed.  This
control fails to properly parse data supplied to the
'RunAndUploadFile()' function due to an unsafe call to 'strcat', which
can lead to a stack-based buffer overflow.

By tricking a user into opening a specially crafted web page, a
remote, unauthenticated attacker could execute arbitrary code on the
remote host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-040/");
  # http://www-01.ibm.com/common/ssi/cgi-bin/ssialias?subtype=ca&infotype=an&appname=iSource&supplier=897&letternum=ENUS911-055
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ffe4d481");
  script_set_attribute(attribute:"solution", value:"Remove or disable the control as fixes are not available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'IBM Tivoli Provisioning Manager Express for Software Distribution Isig.isigCtl.1 ActiveX RunAndUploadFile() Method Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_provisioning_manager_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_activex_func.inc');
include('misc_func.inc');
include('global_settings.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (activex_init() != ACX_OK) exit(1, 'activex_init() failed.');

clsid = '{84B74E82-3475-420E-9949-773B4FB91771}';

# Make sure the control is installed
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed since the class id '"+clsid+"' is not defined on the remote host.");
}

# Get its version
version = activex_get_fileversion(clsid:clsid);
if (!version) version = 'unknown';

info = "";
if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info +=
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file +
    '\n  Installed version : ' + version + '\n';
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
else exit(0, "The control is installed, but its kill bit is set.");
