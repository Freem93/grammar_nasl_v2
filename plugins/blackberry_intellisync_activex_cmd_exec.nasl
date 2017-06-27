#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42370);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2009-0306");
  script_bugtraq_id(36903);
  script_osvdb_id(59748);
  script_xref(name:"Secunia", value:"37244");

  script_name(english:"BlackBerry Desktop Manager Intellisync ActiveX Control Arbitrary Remote Code Execution");
  script_summary(english:"Checks for the control");
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has an ActiveX control that is allows remote
execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The version of the Lotus Notes Intellisync component
('lnsresobject.dll') included with the BlackBerry Desktop Software
installation on the remote host reportedly contains an unspecified 
error that can be exploited to execute arbitrary code.

If an attacker can trick a user on the affected host into viewing a
specially crafted HTML document, he can leverage this issue to execute
arbitrary code on the affected system subject to the user's
privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.blackberry.com/btsc/viewContent.do?externalId=KB19701"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to BlackBerry Desktop Software version 5.0.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/11/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/11/04"
  );
 script_cvs_date("$Date: 2015/01/15 16:37:15 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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


clsid = '{158CD9E8-E195-4E82-9A78-0CF6B86B3629}';
fixed_version = "7.1.1.129";


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


# And check it.
rc = activex_check_fileversion(clsid:clsid, fix:fixed_version);
activex_end();

if (rc == TRUE)
{
  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "\n",
      "  Class Identifier  : ", clsid, "\n",
      "  Filename          : ", file, "\n",
      "  Installed version : ", version, "\n",
      "  Fixed version     : ", fixed_version, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "\n",
      "  Class Identifier  : ", clsid, "\n",
      "  Filename          : ", file, "\n",
      "  Installed version : ", version, "\n",
      "  Fixed version     : ", fixed_version, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report)
  {
    if (report_verbosity > 0) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
    exit(0);
  }
  else exit(0, "A vulnerable version of the control is installed but its kill bit is set.");
}
else if (isnull(rc)) exit(1, "activex_check_fileversion() returned NULL.");
else if (rc == FALSE) exit(0, "The control is not affected since its version is "+version+".");
