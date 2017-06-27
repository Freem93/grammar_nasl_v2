#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51894);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2011/09/01 19:29:14 $");

  script_cve_id("CVE-2010-2931");
  script_bugtraq_id(42109);
  script_osvdb_id(66810);
  script_xref(name:"EDB-ID", value:"14514");
  script_xref(name:"Secunia", value:"40818");

  script_name(english:"SigPlus Pro ActiveX Control LCDWriteString() Method HexString Parameter Overflow");
  script_summary(english:"Checks version of SigPlus control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is vulnerable to
a buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SigPlus Pro ActiveX control, used for electronic signature
integration with Topaz signature pads and installed on the remote
Windows host, is earlier than 3.95.  A stack-based buffer overflow in
such versions reportedly allows execution of arbitrary code via an
overly long value for the 'HexString' argument to the 'LCDWriteString'
method."
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to SigPlus Pro ActiveX version 3.95 or later as that is
reported to address this issue."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");
if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


clsid = '{69A40DA3-4D42-11D0-86B0-0000C025864A}';
fixed_version = "3.95.0.0";
fixed_version_ui = "3.95";

# Locate the file used by the control.
file = activex_get_filename(clsid:clsid);
if (isnull(file))
{
  activex_end();
  exit(1, "activex_get_filename() returned NULL.");
}
if (!file)
{
  activex_end();
  exit(0, "The control is not installed as the class id '"+clsid+"' is not defined on the remote host.");
}


# Get its version.
version = activex_get_fileversion(clsid:clsid);
if (!version)
{
  activex_end();
  exit(1, "Failed to get file version of '"+file+"'.");
}
match = eregmatch(pattern:"^4\.([0-9])\.([0-9])\.0$", string:version);
if (match) version_ui = "4." + match[1] + match[2];
else if (version =~ "^[0-3]\.") version_ui = ereg_replace(pattern:"(\.0){0,2}$", replace:"", string:version);
else version_ui = version;


# And check it.
info = '';

rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
if (rc == TRUE)
{
  if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0)
  {
    info += '\n  Class Identifier  : ' + clsid +
            '\n  Filename          : ' + file + 
            '\n  Installed version : ' + version_ui + 
            '\n  Fixed version     : ' + fixed_version_ui + '\n';
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
  if (rc == FALSE) exit(0, "The control is not affected since it is version "+version_ui+".");
  else if (rc == TRUE) exit(0, "Version "+version_ui+" of the control is installed, but its kill bit is set.");
  else exit(1, "activex_check_fileversion() failed.");
}
