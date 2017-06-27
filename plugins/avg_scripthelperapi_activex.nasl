#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76589);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/07/18 14:14:46 $");

  script_cve_id("CVE-2014-2956");
  script_bugtraq_id(68421);
  script_osvdb_id(108787);
  script_xref(name:"CERT", value:"960193");

  script_name(english:"AVG 'ScriptHelperApi' ActiveX Remote Code Execution");
  script_summary(english:"Checks the version of 'ScriptHelperApi' ActiveX control.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of AVG Secure Search toolbar /
AVG Safeguard, prior to version 18.1.7. The AVG ScriptHelperApi ActiveX
control distributed with the software is affected by a remote code
execution vulnerability. The installed ActiveX control fails to
properly enforce restrictions on websites that can invoke its methods.
An attacker may exploit this issue in order to execute arbitrary code
within the context of the application.");
  script_set_attribute(attribute:"solution", value:
"Upgrade AVG Secure Search toolbar / AVG Safeguard to version
18.1.7.598 / 18.1.7.644 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:avg:secure_search_toolbar");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:avg:safeguard");
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

clsid = "{F25AF245-4A81-40DC-92F9-E9021F207706}";

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

if (report_paranoia <= 1)
{
  killbit = activex_get_killbit(clsid:clsid);
  if (killbit == -1)
  {
    activex_end();
    audit(AUDIT_FN_FAIL, 'activex_get_killbit', -1);
  }
}

activex_end();

cutoff = '18.1.7.0';
fixed = '18.1.7.598 / 18.1.7.644';

# Versions through 18.1.6 are vulnerable, cutoff at 18.1.7.
if (ver_compare(ver:ver, fix:cutoff, strict:FALSE) == -1)
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
  else if (killbit == 0)
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
    if (report_verbosity > 0) security_hole(port:port, extra:report);
    else security_hole(port);
  }
  else audit(AUDIT_ACTIVEX, ver);
}
else audit(AUDIT_INST_VER_NOT_VULN, file, ver);
