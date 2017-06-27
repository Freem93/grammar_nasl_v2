#
#  (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26012);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2007-3168", "CVE-2007-3169");
  script_bugtraq_id(24229, 24230);
  script_xref(name:"EDB-ID", value:"4009");
  script_xref(name:"EDB-ID", value:"4010");
  script_xref(name:"OSVDB", value:"36044");
  script_xref(name:"OSVDB", value:"36045");

  script_name(english:"Office Viewer Component < 5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Office Viewer Component ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Office Viewer Component, an ActiveX
control for working with Microsoft Office documents. 

The version of this control installed on the remote host contains a
buffer overflow in its 'HttpDownloadFile' method that could be
exploited to execute arbitrary code remotely if an attacker can trick
a user on the affected host into visiting a specially crafted web
page. 

In addition, it also allows an attacker to delete arbitrary files via
the 'DeleteLocalFile' method." );
 script_set_attribute(attribute:"see_also", value:"http://moaxb.blogspot.com/2007/05/moaxb-28-edraw-office-viewer-component.html" );
 script_set_attribute(attribute:"see_also", value:"http://moaxb.blogspot.com/2007/05/moaxb-29-edraw-office-viewer-component.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.ocxt.com/archives/28" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Office Viewer Component version 5 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);


 script_set_attribute(attribute:"plugin_publication_date", value: "2007/09/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/05/28");
 script_cvs_date("$Date: 2014/08/15 21:51:08 $");
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


include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsid = "{053AFEBA-D968-435F-B557-19FF76372B1B}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"5.0.0.0") == TRUE)
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
