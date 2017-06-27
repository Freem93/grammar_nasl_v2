#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11143);
 script_version("$Revision: 1.40 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0368");
 script_bugtraq_id(4881);
 script_osvdb_id(863);
 script_xref(name:"CERT", value:"779163");
 script_xref(name:"MSFT", value:"MS02-025");
 script_xref(name:"MSKB", value:"320436");

 script_name(english:"MS02-025: Exchange 2000 Exhaust CPU Resources (320436)");
 script_summary(english:"Checks for MS Hotfix Q320436, DOS on Exchange 2000");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to launch a denial of service attack against the remote
mail server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Exchange Server 2000.  The remote version
of this software contains a flaw that allows an attacker to cause a
temporary denial of service.

To do this, the attacker needs to send an email message with malformed
attributes.  CPU utilization will spike at 100% until the message has
been processed.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-025");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Exchange 2000.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/05/29");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/05/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/10/24");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-025';
kb = '320436';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


server = hotfix_check_nt_server();
if (!server) exit (0);

version = get_kb_item ("SMB/Exchange/Version");
if (!version || (version != 60)) exit (0, "Exchange is not affected based on its version.");

sp = get_kb_item ("SMB/Exchange/SP");
if (sp && (sp >= 3)) exit (0, "Exchange is not affected based on its SP.");


if (is_accessible_share())
{
 path = get_kb_item ("SMB/Exchange/Path") + "\bin";
 if ( hotfix_is_vulnerable(os:"5.0", file:"Exprox.dll", version:"6.0.5770.91", dir:path, bulletin:bulletin, kb:kb) )
 {
 set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
 hotfix_security_warning();
 hotfix_check_fversion_end();
 exit(0);
 }
 hotfix_check_fversion_end();
 exit(0, "The host is not affected.");
}
else exit(1, "is_accessible_share() failed.");


