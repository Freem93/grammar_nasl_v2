#
# This script was written by Douglas Minderhout <dminderhout@layer3com.com>
# This script is based on a previous script written by Renaud Deraison <deraison@cvs.nessus.org>
#
# Thanks to: H D Moore
#
# See the Nessus Scripts License for details
#
# Ref: 
# Message-ID: <1043650912.3e34d960788ac@webmail.web-sale.dk>
# Date: Mon, 27 Jan 2003 08:01:52 +0100
# Subject: [VulnWatch] Multiple vulnerabilities found in PlatinumFTPserver V1.0.7

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (1/31/2009)


include("compat.inc");

if(description){
 script_id(11200);
 script_version ("$Revision: 1.13 $");
 script_osvdb_id(51664, 51665);
 
 script_name(english:"PlatinumFTPServer Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"Platinum FTP server for Win32 has several vulnerabilities in the way it
checks the format of command strings passed to it. 
This leads to the following vulnerabilities in the server :

- The 'dir' command can be used to examine the filesystem of the machine
  and gather further information about the host by using relative
  directory listings.
  (i.e. '../../../' or '\..\..\..').

- The 'delete' command can be used to delete any file on the server that
  the Platinum FTP server has permissions to.

- Issuing the command  'cd @/..@/..' will cause the Platinum FTP server 
  to crash and consume all available CPU time on the server.

*** Warning : Nessus solely relied on the banner of this server, so
*** this may be a false positive" );
 script_set_attribute(attribute:"solution", value:
"See http://www.platinumftp.com/platinumftpserver.php" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:C");
		 
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/01/18");
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 
 script_summary(english:"Checks if the remote ftp server is a vulnerable version of Platinum FTP");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 script_copyright(english:"This script is Copyright (C) 2003-2013 Douglas Minderhout");
		  
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if(banner) {
	if(egrep(pattern:"^220.*PlatinumFTPserver V1\.0\.[0-7][^0-9].*$",string:banner)) {
 		
  		security_hole(port);
   	}
}
