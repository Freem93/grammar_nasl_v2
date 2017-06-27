#
# (C) Tenable Network Security, Inc.
#

if ( ! defined_func("bn_random") ) exit(0);


include("compat.inc");

if(description)
{
 script_id(19702);
 script_version("$Revision: 1.14 $");

 script_cve_id(
   "CVE-2005-2527", 
   "CVE-2005-2528", 
   "CVE-2005-2529", 
   "CVE-2005-2530", 
   "CVE-2005-2738"
 );
 script_bugtraq_id(14825, 14826, 14827);
 script_osvdb_id(19393, 19394, 19395, 19396, 19397);

 script_name(english:"Mac OS X : Java for Mac OS X 1.3.1 and 1.4.2 Release 2 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is missing a security bugfix for Java 1.4.2 and 1.3.1. 

This update fixes several security vulnerabilities that may allow a
Java applet to escalate its privileges. 

To exploit these flaws, an attacker would need to lure an attacker
into executing a rogue Java applet." );
 # http://web.archive.org/web/20080214202402/http://docs.info.apple.com/article.html?artnum=302265
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbb98bf2" );
 # http://web.archive.org/web/20080214202407/http://docs.info.apple.com/article.html?artnum=302266
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fd9e3bf" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Java 1.3.1 / 1.4.2 Release 2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/09/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/09/02");
 script_set_attribute(attribute:"patch_publication_date", value: "2005/09/13");
 script_cvs_date("$Date: 2016/11/28 21:06:38 $");
script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();

 
 script_summary(english:"Check for Java 1.4.2");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"MacOS X Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/MacOSX/packages");
 exit(0);
}


packages = get_kb_item("Host/MacOSX/packages");
if ( ! packages ) exit(0);

uname = get_kb_item("Host/uname");
# Mac OS X 10.3.9 and 10.4.2 only
if ( egrep(pattern:"Darwin.* 7\.[0-9]\.", string:uname) )
{
  if ( !egrep(pattern:"^JavaSecurityUpdate4\.pkg", string:packages) ) security_hole(0);
}
else if ( egrep(pattern:"Darwin.* 8\.[0-2]\.", string:uname) )
{
  if ( !egrep(pattern:"^Java131and142Release2\.pkg", string:packages) ) security_hole(0);
}
