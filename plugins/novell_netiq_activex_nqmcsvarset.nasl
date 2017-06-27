#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74261);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/23 19:31:45 $");

  script_cve_id("CVE-2014-3460");
  script_bugtraq_id(67487);
  script_osvdb_id(107095);

  script_name(english:"Novell NetIQ Sentinel Agent Manager NQMcsVarSet ActiveX DumpToFile() Remote Code Execution");
  script_summary(english:"Checks the kill bit for NQMcsVarSet ActiveX control");
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host contains the NQMcsVarSet ActiveX control distributed
with Novell NetIQ Sentinel Agent Manager.

The installed control is reportedly affected by a remote code
execution vulnerability with the DumpToFile method where it does not
properly sanitize the path for a filename. This could allow a remote
attacker, with a specially crafted file or site, to traverse the
directories to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-14-134/");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7015183");
  script_set_attribute(attribute:"solution", value:
"Update Novell NetIQ Sentinel Agent Manager to version 7.2 or later, or
ensure the kill bit has been set for the NQMcsVarSet ActiveX Control.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netiq:sentinel_agent_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

clsid = "{B4B7CF9E-AD9E-11D8-AE3B-005056C00008}";

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

ver = activex_get_fileversion(clsid:clsid);
if (isnull(ver))
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

activex_end();

fixed = '7.2.0.463';

if (ver_compare(ver:ver, fix:fixed, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  report = NULL;

  if (report_paranoia > 1)
  {
    report =
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fixed +
      '\n' +
      '\n' + 'Note, though, that Nessus did not check whether the kill bit was' +
      '\n' + 'set for the control\'s CLSID because of the Report Paranoia setting' +
      '\n' + 'in effect when this scan was run.\n';
  }
  else if (killbit ==0)
  {
    report =
      '\n  Class identifier  : ' + clsid +
      '\n  Filename          : ' + file +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fixed +
      '\n' +
      '\n' + 'Its kill bit is not set so it is accessible via Internet Explorer.\n';
  }

  if (report)
  {
    if (report_verbosity > 0) security_warning(port:port, extra:report);
    else security_warning(port);
  }
  else audit(AUDIT_ACTIVEX, ver);
}
else audit(AUDIT_INST_VER_NOT_VULN, file, ver);
