#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26969);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-3675");
  script_bugtraq_id(26004);
  script_osvdb_id(37713);

  script_name(english:"Kaspersky Online Scanner kavwebscan.CKAVWebScan ActiveX (kavwebscan.dll) Format String Arbitrary Code Execution");
  script_summary(english:"Checks version of Kaspersky Web Scanner control");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by a
format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the Kaspersky Online Scanner, an online virus
scanner for Windows. 

The version of the Kaspersky Web Scanner ActiveX control installed as
part of this software on the remote host contains a format string
vulnerability.  By tricking a user on the affected host into visiting 
a specially crafted web page, an attacker may be able to use this 
method to execute arbitrary code on the affected system subject to the 
user's privileges." );
  # http://www.nessus.org/u?de2e5272
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de2e5272" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Oct/148" );
 script_set_attribute(attribute:"see_also", value:"http://www.kaspersky.com/news?id=207575572" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kaspersky Online Scanner version 5.0.98.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(134);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/10/11");
 script_cvs_date("$Date: 2016/10/27 15:03:54 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:online_scanner");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

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

clsid = "{0EB0E74A-2A76-4AB3-A7FB-9BD8C29F7F75}";
file = activex_get_filename(clsid:clsid);
if (file)
{
  # Check its version.
  ver = activex_get_fileversion(clsid:clsid);
  if (ver && activex_check_fileversion(clsid:clsid, fix:"5.0.98.0") == TRUE)
  {
    report = string(
      "\n",
      "Version ", ver, " of the vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n"
    );
    security_hole(port:kb_smb_transport(), extra:report);
  }
}
activex_end();
