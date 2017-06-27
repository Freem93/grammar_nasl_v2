#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25688);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2007-1754");
 script_bugtraq_id(22702);
 script_osvdb_id(35953);
 script_xref(name:"MSFT", value:"MS07-037");

 script_name(english:"MS07-037: Vulnerability in Microsoft Publisher Could Allow Remote Code Execution (936548)");
 script_summary(english:"Determines the version of MSPUB.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Publisher.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Publisher that may
allow arbitrary code to be run.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-037");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Publisher 2007.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/07/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-037';
kbs = make_list("936646");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

port = get_kb_item("SMB/transport");

list = get_kb_list_or_exit('SMB/Office/Publisher/*/ProductPath');
foreach item (keys(list))
{
  v = item - 'SMB/Office/Publisher/' - '/ProductPath';
  if(ereg(pattern:"^12\..*", string:v))
  {
    # Publisher 2007 - fixed in 12.0.6023.5000
    middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
    low =  ereg_replace(pattern:"^12\.0\.[0-9]*\.([0-9]*)$", string:v, replace:"\1");
    if(middle != v && int(middle) < 6023 || ( int(middle) == 6023 && int(low) < 5000)) {
      set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
      info =
        '\n  Product           : Publisher 2007' +
        '\n  Installed version : ' + v +
        '\n  Fixed version     : 12.0.6023.5000\n';
      hotfix_add_report(info, bulletin:'MS07-037', kb:'936646');
      hotfix_security_hole();
      exit(0);
    }
  }
}
audit(AUDIT_HOST_NOT, 'affected');
