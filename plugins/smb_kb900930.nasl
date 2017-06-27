#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18680);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-2226");
 script_bugtraq_id(14225);
 script_xref(name:"OSVDB", value:"18241");

 script_name(english:"MS KB900930: Microsoft Outlook Express Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"A denial of service attack can be launched against the remote Outlook
Express install." );
 script_set_attribute(attribute:"description", value:
"The remote host runs a version of Outlook Express that contains
multiple vulnerabilities. 

An attacker may exploit these vulnerabilities to disable the Outlook
Express client of a victim. 

To exploit these issues, an attacker would need to send a malformed
email message to a victim and wait for him to read it using outlook." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP :

http://support.microsoft.com/kb/900930/EN-US/" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/07/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/07/12");
 script_cvs_date("$Date: 2012/09/14 15:15:51 $");
script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:outlook_express");
script_end_attributes();
 
 script_summary(english:"Checks for Microsoft Hotfix 900930");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("smb_nt_ms05-030.nasl");
 script_require_keys("SMB/OutlookExpress/MSOE.dll/Version");
 exit(0);
}

#

v = get_kb_item("SMB/OutlookExpress/MSOE.dll/Version");
if ( ! v ) exit(0);

vi = split(v, sep:".", keep:0);
if ( int(vi[0]) == 6 && int(vi[1]) == 0 && int(v[2]) < 3790 && int(v[2]) >= 2800 )
{
 if ( int(v[2]) < 2900 || (int(v[2]) == 2900 &&  int(v[3]) < 2670))
	security_warning(port:get_kb_item("SMB/transport"));
}
