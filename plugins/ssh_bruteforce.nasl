#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable
# - Updated to use compat.inc (11/20/2009)



include("compat.inc");

if(description)
{
 script_id(11341);
 script_version ("$Revision: 1.15 $");

 script_cve_id("CVE-2001-0471");
 script_bugtraq_id(2345);
 script_osvdb_id(8038);
 
 name["english"] = "SSH1 SSH Daemon Logging Failure";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote SSH server does not properly log repeated logins attempts." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SSH Communications Security SSH 1.2.30 or
older. 

The remote version of this software does not log repeated login
attempts, which could allow remote attackers to compromise accounts
without detection via a brute-force attack." );
 #https://web.archive.org/web/20010311131915/http://archives.neohapsis.com/archives/bugtraq/2001-02/0084.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc4157ec" );
 script_set_attribute(attribute:"solution", value:
"Upgrade the remote SSH server to the newest version available from
SSH.com" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/05");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for the remote SSH version";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Xue Yong Zhi");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 script_dependencie("ssh_detect.nasl");
 script_require_ports("Services/ssh", 22);
 exit(0);
}

#
# The script code starts here
#

include("backport.inc");
port = get_kb_item("Services/ssh");
if(!port)port = 22;

banner = get_kb_item("SSH/banner/" + port );
if ( ! banner ) exit(0);
banner = get_backport_banner(banner:banner);

if ( "openssh" >< tolower(banner) ) exit(0);


#Looking for SSH product version number from 1.0 to 1.2.30
if(ereg(string:banner,
  	pattern:"^SSH-[0-9]\.[0-9]+-1\.([0-1]|[0-1]\..*|2\.([0-9]|1[0-9]|2[0-9]|30))[^0-9]*$", icase:TRUE))security_hole(port);



