#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26198);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2007-4821");
  script_bugtraq_id(25593);
  script_xref(name:"EDB-ID", value:"4373");
  script_xref(name:"OSVDB", value:"38832");

  script_name(english:"EDraw Office Viewer ActiveX (officeviewer.ocx) HttpDownloadFileToTempDir Method Overflow");
  script_summary(english:"Checks version of EDraw Office Viewer Component control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the EDraw Office Viewer Component, an ActiveX
control for working with Microsoft Office documents.

The version of this control installed on the remote host contains a
buffer overflow that can be triggered by a long value for the first
argument of the 'HttpDownloadFileToTempDir' method.  If an attacker
can trick a user on the affected host into visiting a specially
crafted web page, this method could be leveraged to execute
arbitrary code on the affected system subject to the user's
privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.ocxt.com/archives/48" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to EDraw Office Viewer Component 5.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/09/07");
 script_cvs_date("$Date: 2014/06/06 18:38:43 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

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

clsid = "{6BA21C22-53A5-463F-BBE8-5CF7FFA0132B}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"5.3.220.1") == TRUE)
  {
    report = string(
      "Version ", ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n"
    );
    security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
