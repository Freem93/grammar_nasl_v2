#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(36073);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-4475");
  script_bugtraq_id(34310);
  script_osvdb_id(53066, 62677, 62678);
  script_xref(name:"CERT", value:"985449");
  script_xref(name:"Secunia", value:"34559");

  script_name(english:"SAP GUI Moniker Creation Multiple Vulnerabilities");
  script_summary(english:"Checks for control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities. " );
  script_set_attribute(attribute:"description", value:
"The version of the SAP GUI Moniker Creation ActiveX control installed
on the remote Windows host is reportedly affected by 3 stack-based 
buffer overflows involving various properties and methods in
'MonikerUtil_dll.dll'.  If an attacker can trick a user on the
affected host into viewing a specially crafted HTML document, he can
leverage these issues to execute arbitrary code subject to the user's
privileges." );
  script_set_attribute(attribute:"see_also", value:"http://www.attrition.org/pipermail/vim/2009-September/002260.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to SAP GUI 7.10 Patch Level 9 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'SAP AG SAPgui EAI WebViewer3D Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/03/31"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/03/31"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/04/01"
  );
 script_cvs_date("$Date: 2014/04/17 21:56:22 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:sap:sapgui");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

#Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{AFBBE070-7340-11d2-AA6B-00E02924C34E}';
file = activex_get_filename(clsid:clsid);
if (file)
{
  ver = activex_get_fileversion(clsid:clsid);

  if (ver) ver = string("Version ", ver);
  else ver = string("An unknown version");

  report = NULL;
  if (report_paranoia > 1)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Note, though, that Nessus did not check whether the kill bit was \n",
      "set for the control's CLSID because the Report Paranoia setting \n",
      "was in effect when this scan was run.\n"
    );
  else if(activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "\n",
      ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report)
  {
    if (report_verbosity > 0)
      security_hole(port:kb_smb_transport(), extra:report);
    else
      security_hole(kb_smb_transport());
  }
}
activex_end();
