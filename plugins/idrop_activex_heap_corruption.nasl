#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36087);
  script_version("$Revision: 1.12 $");

  script_bugtraq_id(34352);
  script_xref(name:"OSVDB", value:"53265");
  script_xref(name:"Secunia", value:"34563");

  script_name(english:"Autodesk IDrop ActiveX Control Heap Corruption");
  script_summary(english:"Checks for the control");
 
  script_set_attribute( attribute:"synopsis",  value:
"The remote Windows host has an ActiveX control that is affected by a
heap corruption vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The IDrop ActiveX control, a utility from Autodesk that provides the
ability to drag and drop web content into a drawing session, is
installed on the remote Windows host. 

Manipulation of the control's 'Src', 'Background', and 'PackageXml'
properties reportedly can be abused to trigger a heap-use-after-free
condition.  If an attacker can trick a user on the affected host into
viewing a specially crafted HTML document, he can leverage this issue
to execute arbitrary code on the affected system subject to the user's
privileges."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/502414/30/0/threaded"
  );
  script_set_attribute( attribute:"solution",  value:
"Remove the affected software as it reportedly is no longer supported
by Autodesk."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Autodesk IDrop ActiveX Control Heap Memory Corruption');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/04/06");
 script_cvs_date("$Date: 2014/04/17 21:56:22 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
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


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = '{21E0CB95-1198-4945-A3D2-4BF804295F78}';
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
      "Note, though, that Nessus did not check whether the kill bit was\n",
      "set for the control's CLSID because of the Report Paranoia setting\n",
      "in effect when this scan was run.\n"
    );
  else if (activex_get_killbit(clsid:clsid) == 0)
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
    if (report_verbosity) security_hole(port:kb_smb_transport(), extra:report);
    else security_hole(kb_smb_transport());
  }
}
activex_end();
