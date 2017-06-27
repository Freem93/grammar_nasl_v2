#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47899);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2010-0126", "CVE-2010-0133", "CVE-2010-0134", "CVE-2010-0135", "CVE-2010-0131", "CVE-2010-1524", "CVE-2010-1525");
  script_bugtraq_id(41928);
  script_osvdb_id(67246, 67247, 67248, 67249, 67250, 67251, 67252);

  script_name(english:"Autonomy KeyView Filter Module Multiple Memory Corruption Vulnerabilities (Lotus Notes)");
  script_summary(english:"Checks version of DLLs shipped with Lotus Notes"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a DLL that is affected by several buffer
overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Lotus Notes installed on the remote Windows host ships
with several DLL designed to perform file conversions ('Autonomy
KeyView Filter'). 

Specifically, these DLLs are affected by several overflow
vulnerabilities that may allow an attacker to execute arbitrary code
on the remote host. 

To exploit these vulnerabilities, an attacker would need to send a
specially malformed document to a user on the remote host and wait for
him to open it via Notes.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21440812");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-16/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-27/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-49/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-28/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-35/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2010-31/");
  script_set_attribute(attribute:"solution", value: "Apply the patch from IBM");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/29");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "lotus_notes_installed.nasl");
  script_require_keys("SMB/name", "SMB/login", "SMB/password","SMB/Lotus_Notes/Installed","Settings/ParanoidReport");
  script_require_ports("Services/notes", 139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

if ( report_paranoia < 2 ) audit(AUDIT_PARANOID);

appname = "IBM Lotus Notes";
kb_base = "SMB/Lotus_Notes/";

path = get_kb_item_or_exit(kb_base + 'Path');
version = get_kb_item_or_exit(kb_base + 'Version');

dlls = make_array("kpmsordr.dll", "8.5.14.10206",
	                "mwsr.dll", "8.5.14.10206",
	                "wkssr.dll", "8.5.14.10206",
	                "kvolefio.dll", "8.5.14.10206",
	                "qpssr.dll", "8.5.14.10206",
	                "wosr.dll", "8.5.14.10206");

flag = 0;
report = '';

foreach dll (keys(dlls))
{
 if ( hotfix_check_fversion(file:dll, version:dlls[dll], path:path) == HCF_OLDER )
   flag = 1;
}

hotfix_check_fversion_end();

if ( flag ) hotfix_security_hole();
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
