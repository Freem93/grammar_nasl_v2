#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(26914);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-5082", "CVE-2007-5083", "CVE-2007-5084");
  script_bugtraq_id(25823);
  script_osvdb_id(41363, 41364, 41365);

  script_name(english:"BrightStor Hierarchical Storage Manager < r11.6 Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version reported by CsAgent");

 script_set_attribute(attribute:"synopsis", value:
"The remote data migration service is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"According to its engine build, the installation of BrightStor
Hierarchical Storage Manager on the remote host has multiple
vulnerabilities affecting its CsAgent service, including buffer
overflows and SQL injection vulnerabilities.  An unauthenticated
remote attacker may be able to leverage these issues to run arbitrary
SQL commands, crash the affected service, or even execute arbitrary
code with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?706b6c19" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Sep/384" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Oct/26" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Oct/27" );
 script_set_attribute(attribute:"see_also", value:"http://www.ca.com/securityadvisor/newsinfo/collateral.aspx?cid=156444" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BrightStor Hierarchical Storage Manager r11.6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'CA BrightStor HSM Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(89, 119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/10/04");
 script_cvs_date("$Date: 2016/11/18 21:06:04 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
  script_dependencies("csagent_udp_detect.nasl");
  script_require_ports("Services/udp/hsm_csagent");

  exit(0);
}


port = get_kb_item("Services/udp/hsm_csagent");
if (!port) exit(0);


# There's a problem if the build uses a date before 2007.
build = get_kb_item("Services/hsm_csagent/" + port + "/build");
if (
  build && 
  build =~ "^[0-9]+ +[01][0-9]/[0-3][0-9]/(1[099]{3}|200[0-6])$"
) {
 security_hole(port:port, protocol:"udp");
 set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
}

