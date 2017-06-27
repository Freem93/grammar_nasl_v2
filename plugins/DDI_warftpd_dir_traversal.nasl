#
# This script was written by Erik Tayler <erik@digitaldefense.net>
#
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Revised plugin title (2/04/2009)

include("compat.inc");

if(description)
{
	script_id(11206);
	script_version("$Revision: 1.16 $");

	script_cve_id("CVE-2001-0295");
	script_bugtraq_id(2444);
	script_osvdb_id(874);
	
	script_name(english:"WarFTPd dir Command Traversal Arbitrary Directory Listing");
	script_summary(english:"WarFTPd Directory Traversal");

	script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is prone to directory traversal attack.");
	script_set_attribute(attribute:"description", value:
"The version of WarFTPd running on this host contains a vulnerability
that may allow a potential intruder to gain read access to directories
and files outside of the ftp root.  By sending a specially crafted
'dir' command, the server may disclose an arbitrary directory.");
	script_set_attribute(attribute:"see_also", value:
"http://seclists.org/bugtraq/2001/Mar/72");
	script_set_attribute(attribute:"solution", value:
"Upgrade to WarFTPd version 1.67 b5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2003/01/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/03/06");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_ATTACK);
	script_copyright(english:"This script is Copyright (C) 2003-2011 Digital Defense, Inc.");
	script_family(english:"FTP");
	script_dependencies("ftpserver_detect_type_nd_version.nasl");
	script_require_ports("Services/ftp", 21);
	exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);

r = get_ftp_banner(port:port);
if (! r) exit(1);

	if( (egrep(pattern:"WAR-FTPD 1\.(6[0-5]|[0-5].*)",string:r)) || ("WAR-FTPD 1.67-04" >< r) )
	{
		security_warning(port);
	}
