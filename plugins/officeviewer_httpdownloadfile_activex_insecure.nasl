#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26013);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-4420");
  script_bugtraq_id(25344);
  script_xref(name:"EDB-ID", value:"4290");
  script_xref(name:"OSVDB", value:"38794");

  script_name(english:"Office Viewer Component ActiveX (officeviewer.ocx) HttpDownloadFile Method Traversal Arbitrary File Overwrite");
  script_summary(english:"Checks version of Office Viewer Component ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control with an insecure
method." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Office Viewer Component, an ActiveX
control for working with Microsoft Office documents.

The version of this control installed on the remote host reportedly
contains an insecure method, 'HttpDownloadFile'.  If an attacker can
trick a user on the affected host into visiting a specially crafted
web page, he may be able to use this method to place arbitrary files
on the host subject to the user's privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.ocxt.com/archives/39" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Office Viewer Component version 5.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(22);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/08/16");
 script_cvs_date("$Date: 2016/05/20 14:21:42 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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
  if (ver && activex_check_fileversion(clsid:clsid, fix:"5.2.219.1") == TRUE)
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
