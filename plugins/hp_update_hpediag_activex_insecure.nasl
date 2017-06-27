#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(32055);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2008-0712");
  script_bugtraq_id(28929);
  script_osvdb_id(44662, 44663, 44664, 44665, 44666, 44767);

  script_name(english:"HP HPeDiag ActiveX Control Multiple Vulnerabilities");
  script_summary(english:"Checks whether kill bit is set for HPeDiag ActiveX control"); 
 
 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows reading and
writing of arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The remote host contains the HP Software Update software, installed by
default on many HP notebooks to support automatic software updates and
vulnerability patching. 

The version of this software on the remote host includes an ActiveX
control, 'HpeDiag', that reportedly contains multiple insecure
methods - 'ReadTextFile()' and 'WriteTextFile()' - that are marked as
'Safe for Scripting' and allow for reading and overwriting arbitrary
files on the affected system.  If a remote attacker can trick a user
on the affected host into visiting a specially crafted web page, this
issue could be leveraged to effectively destroy arbitrary files on 
the remote host, potentially even files that are vital for its 
operation, or to read the contents of arbitrary files." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/14540" );
 script_set_attribute(attribute:"solution", value:
"Either use HP Software Update itself to update the software or disable
use of this ActiveX control from within Internet Explorer by setting
its kill bit." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2008/04/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/04/24");
 script_cvs_date("$Date: 2014/04/17 18:47:26 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:software_update");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(0);

clsids = make_list(
"{60178279-6D62-43af-A336-77925651A4C6}",
"{DC4F9DA0-DB05-4BB0-8FB2-03A80FE98772}",
"{0C378864-D5C4-4D9C-854C-432E3BEC9CCB}",
"{93441C07-E57E-4086-B912-F323D741A9D8}",
"{CDAF9CEC-F3EC-4B22-ABA3-9726713560F8}",
"{CF6866F9-B67C-4B24-9957-F91E91E788DC}",
"{A95845D8-8463-4605-B5FB-4F8CFBAC5C47}",
"{B9C13CD0-5A97-4C6B-8A50-7638020E2462}",
"{C70D0641-DDE1-4FD7-A4D4-DA187B80741D}",
"{DE233AFF-8BD5-457E-B7F0-702DBEA5A828}",
"{AB049B11-607B-46C8-BBF7-F4D6AF301046}",
"{910E7ADE-7F75-402D-A4A6-BB1A82362FCA}",
"{42C68651-1700-4750-A81F-A1F5110E0F66}",
"{BF931895-AF82-467A-8819-917C6EE2D1F3}",
"{4774922A-8983-4ECC-94FD-7235F06F53A1}",
"{E12DA4F2-BDFB-4EAD-B12F-2725251FA6B0}",
"{C94188F6-0F9F-46B3-8B78-D71907BD8B77}",
"{6470DE80-1635-4B5D-93A3-3701CE148A79}",
"{17E67D4A-23A1-40D8-A049-EE34C0AF756A}",
"{AB237044-8A3B-42BB-9EE1-9BFA6721D9ED}",
"{784F2933-6BDD-4E5F-B1BA-A8D99B603649}"
);


foreach clsid (clsids)
{
 file = activex_get_filename(clsid:clsid);
 if (file)
 {
  report = NULL;
  if (activex_get_killbit(clsid:clsid) == 0)
    report = string(
      "The vulnerable control is installed as :\n",
      "\n",
      "  ", file, "\n",
      "\n",
      "Moreover, its kill bit is not set so it is accessible via Internet\n",
      "Explorer.\n"
    );
  if (report) {
	security_hole(port:kb_smb_transport(), extra:report);
	break;
	}
 }
 activex_end();
}
