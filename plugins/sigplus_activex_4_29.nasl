#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51895);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2011/10/24 19:37:29 $");

  script_cve_id("CVE-2011-0323", "CVE-2011-0324");
  script_bugtraq_id(46128);
  script_osvdb_id(72555, 72556);
  script_xref(name:"Secunia", value:"42800");

  script_name(english:"SigPlus Pro ActiveX Control < 4.29 Multiple Vulnerabilities");
  script_summary(english:"Checks version of SigPlus control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SigPlus Pro ActiveX control, used for electronic signature
integration with Topaz signature pads and installed on the remote
Windows host, is earlier than 4.29.  Such versions reportedly are
affected by the following vulnerabilities :

  - The 'SetLogFilePath()' method allows creation of a log
    file in a specified location, potentially with content 
    controlled by an attacker through, for example, the 
    'SigMessage()' method. (CVE-2011-0323)

  - Boundary errors when processing the 'KeyString' 
    property and when handling the 'SetLocalIniFilePath()'
    and 'SetTablePortPath()' methods can be exploited to
    cause a heap-based buffer overflow. (CVE-2011-0324)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2011-1/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://secunia.com/secunia_research/2011-2/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade to SigPlus Pro ActiveX version 4.29 or later as that
reportedly addresses the issues."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/02");
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
fixed_version = "4.2.9.0";
fixed_version_ui = "4.29";

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
