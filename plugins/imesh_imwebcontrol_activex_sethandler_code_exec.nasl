#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(31050);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-6493");
  script_bugtraq_id(26916);
  script_xref(name:"Secunia", value:"28134");
  script_xref(name:"OSVDB", value:"40239");

  script_name(english:"iMesh IMWeb.IMWebControl ActiveX (IMWeb.dll) SetHandler Method Arbitrary Code Execution");
  script_summary(english:"Checks for affected ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows
arbitrary command execution." );
 script_set_attribute(attribute:"description", value:
"The IMWeb.IMWebControl.1 ActiveX control, included with the IMesh
peer-to-peer file sharing application, is installed on the remote
host.  It reportedly allows arbitrary command execution through its
'SetHandler' method.  If a remote attacker can trick a user on the
affected host into visiting a specially crafted web page, he may be
able to leverage this issue to execute arbitrary code on the affected
host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://retrogod.altervista.org/rgod_imesh.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485261/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/13");
 script_cvs_date("$Date: 2014/04/17 21:56:22 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the control.
if (activex_init() != ACX_OK) exit(0);

clsid = "{7C3B01BC-53A5-48A0-A43B-0C67731134B9}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Get its version.
  ver = activex_get_fileversion(clsid:clsid);

  if (ver) ver = string("Version ", ver);
  else ver = string("An unknown version");

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
