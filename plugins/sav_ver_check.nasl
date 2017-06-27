#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
script_id(24236);
script_version("$Revision: 1.18 $");
script_cve_id("CVE-2006-2630");
script_bugtraq_id(18107);
  script_osvdb_id(25846);

script_name(english:"Symantec AntiVirus Management Interface Remote Overflow (SYM06-010)");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a vulnerable version of Symantec AntiVirus." );
 script_set_attribute(attribute:"description", value:
"The remote antivirus is vulnerable to a remote stack-based buffer
overflow attack.  In order to exploit this issue, the attacker needs
to send an overly-long COM_FORWARD_LOG message to the management
interface of the product, which listens on port 2967.  Successful
exploitation of this issue will result in complete compromise of the
system.  This issue was targeted by the 'Big Yellow' worm to gain
complete control of vulnerable systems." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2006.05.25.html" );
 script_set_attribute(attribute:"solution", value:
"Update your Symantec Antivirus product." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Symantec Remote Management Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/25");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/06/12");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/05/24");
 script_cvs_date("$Date: 2014/05/30 21:51:49 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

script_summary(english:"Checks that if a vulnerable version of savce is installed");
script_category(ACT_GATHER_INFO);
script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
script_family(english:"Windows");
script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl","savce_installed.nasl");
script_require_keys("Antivirus/SAVCE/version");

exit(0);
}

#

include("smb_func.inc");

vulnerable_prod_ver_list = make_list("10.0.0.359","10.0.1.1000","10.0.1.1007","10.0.1.1008",
				     "10.0.2.2000","10.0.2.2001","10.0.2.2010","10.0.2.2020",
				     "10.1.0.394","10.1.0.400");


version = get_kb_item("Antivirus/SAVCE/version");
if(!version )exit(0);

foreach prod (vulnerable_prod_ver_list)
{
  if (version == prod)
  {
   report = '\n'+"Remote Product version : "+version;

   security_hole(port:get_kb_item("SMB/transport"), extra:report);
   break;
  }
}

