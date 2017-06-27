#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81787);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/08 14:57:51 $");

  script_cve_id("CVE-2014-8388");
  script_bugtraq_id(71193);
  script_osvdb_id(114842);

  script_name(english:"WebGate Webeye ActiveX Control Stack Based Buffer Overflow Vulnerability");
  script_summary(english:"Checks for the webeye.ocx ActiveX control.");

  script_set_attribute(attribute:"synopsis",value:
"The remote host has an ActiveX control with a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description",value:
"The WebGate 'webeye.ocx' ActiveX control installed on the remote host
is affected by a stack-based buffer overflow vulnerability due to
improperly processing input to the 'ip_address' parameter. A remote
attacker, using specially crafted input, can exploit this to execute
arbitrary code.");
  # http://www.coresecurity.com/advisories/advantech-webAccess-stack-based-buffer-overflow
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?5e5be36d");
  script_set_attribute(attribute:"see_also",value:"https://ics-cert.us-cert.gov/advisories/ICSA-14-324-01");
  script_set_attribute(attribute:"see_also",value:"http://support.microsoft.com/kb/240797");
  script_set_attribute(attribute:"solution",value:
"Uninstall the ActiveX control or disable it by setting the 'killbit'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2014/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:advantech:webaccess");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

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

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

clsid = "{A8739816-022C-11D6-A85D-00C04F9AEAFB}";

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

info = '';

if (ver_compare(ver:ver, fix:"1.0.1.35", strict:FALSE) > 0)
  audit(AUDIT_INST_VER_NOT_VULN, file, ver);

# no known fix available
if(report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
{
  info =
    '\n  Class identifier  : ' + clsid +
    '\n  Filename          : ' + file +
    '\n  Installed version : ' + ver +
    '\n';
}

activex_end();

if (info)
{
  port = kb_smb_transport();
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
else audit(AUDIT_ACTIVEX, ver);
