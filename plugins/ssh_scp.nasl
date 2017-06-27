#
# This script was written by Xue Yong Zhi<xueyong@udel.edu>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (8/7/09)
# - Updated to use compat.inc, added CVSS score (11/20/2009)


include("compat.inc");

if(description)
{
 script_id(11339);
 script_version ("$Revision: 1.11 $");
 script_cve_id("CVE-2000-0992");
 script_bugtraq_id(1742);
 script_osvdb_id(1586);
 
 script_name(english:"sshd scp Traversal Arbitrary File Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a
directory traversal issue." );
 script_set_attribute(attribute:"description", value:
"You are running OpenSSH 1.2.3, or 1.2. 
 
This version has directory traversal vulnerability in scp,
it allows a remote malicious scp server to overwrite arbitrary 
files via a .. (dot dot) attack." );
 script_set_attribute(attribute:"solution", value:
"Patch and New version are available from SSH/OpenSSH." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
	
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/09/30");
 script_cvs_date("$Date: 2011/03/16 13:37:58 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for the remote SSH version");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Xue Yong Zhi");
 script_family(english:"Gain a shell remotely");
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

#Looking for OpenSSH product version number 1.2 and 1.2.3	
if(ereg(pattern:".*openssh[-_](1\.2($|\.3|[^0-9])).*",string:banner, icase:TRUE))security_warning(port);

if(ereg(pattern:".*ssh-.*-1\.2\.(1[0-4]|2[0-7])[^0-9]", string:banner, icase:TRUE))security_warning(port);
