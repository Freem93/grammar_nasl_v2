#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(15867);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2004-1211");
 script_bugtraq_id(11775, 11788);
  script_osvdb_id(12508);
  script_xref(name:"EDB-ID", value:"1375");
 script_xref(name:"Secunia", value:"13348");

 script_name(english:"Mercury Mail Remote IMAP Server Remote Overflow");
 script_summary(english:"Checks for version of Mercury Mail");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote IMAP server has multiple buffer overflow vulnerabilities."
 );
 script_set_attribute(attribute:"description",  value:
"The remote host is running Mercury Mail server, an IMAP server for
Windows.

According to its banner, the version of Mercury Mail running on the
remote host has multiple stack-based buffer overflow vulnerabilities.
A remote, authenticated attacker could exploit these issues to crash
the service or execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Dec/45"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/fulldisclosure/2004/Dec/116"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Mercury/32 v4.01a IMAP RENAME Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/29");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Gain a shell remotely");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service2.nasl");
 script_require_ports("Services/imap", 143);
 script_exclude_keys("imap/false_imap");

 exit(0);
}

#
# The script code starts here
#

include("imap_func.inc");
port = get_kb_item("Services/imap");
if(!port) port = 143;

banner = get_imap_banner(port:port);
if ( ! banner ) exit(0);

if(egrep(pattern:"^\* OK.*IMAP4rev1 Mercury/32 v([0-3]\..*|4\.(00.*|01[^b-z].*))server ready.*", string:banner))
{
  security_hole(port);
}    
