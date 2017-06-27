#
# This script was written by Vincent Renardias <vincent@strongholdnet.com>
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, enhanced description, added OSVDB ref, updated risk with CVSS2 (1/29/2009)



include("compat.inc");

if(description)
{
 script_id(10822);
 script_bugtraq_id(2698);
 script_osvdb_id(687);
 script_version("$Revision: 1.17 $");
 
 name["english"] = "Multiple Vendor FTPD on Windows Floppy Request CPU Consumption DoS";
 
 script_name(english:name["english"]);
             
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server may be vulnerable to a denial of
service." );
 script_set_attribute(attribute:"description", value:
"It is possible for a remote user to cause a denial of
service on a host running Serv-U FTP Server, G6 FTP Server
or WarFTPd Server. Repeatedly submitting an 'a:/' GET or
RETR request, appended with arbitrary data, will cause 
the CPU usage to spike to 100%.

Nessus identified the remote server as running version 1.71
of WarFTPd." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of WarFTPd or contact your 
FTP vendor for details." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
                 
                 
 script_set_attribute(attribute:"plugin_publication_date", value: "2001/12/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/02/17");
 script_cvs_date("$Date: 2011/03/11 20:33:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

                    
 
 script_summary(english:"Checks if the version of the remote warftpd");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 
 script_copyright(english:"This script is Copyright (C) 2001-2011 StrongHoldNET");
                  
 script_require_ports("Services/ftp", 21);
 script_dependencies("ftpserver_detect_type_nd_version.nasl");
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if (! banner) exit(1);

 if(("WarFTPd 1.71" >< banner))
   security_warning(port);

