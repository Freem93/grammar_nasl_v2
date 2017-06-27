#
# This script derived from aix_ftpd by Michael Scheidell at SECNAP
#
# original script  written by Renaud Deraison <deraison@cvs.nessus.org>
# 
# See the Nessus Scripts License for details
#
# Changes by Tenable:
# - Disabled the DoS code, as it will completely crash the
#   remote host, something that should not be done from within
#   a ACT_MIXED_ATTACK plugin. (RD)
# - Revised plugin title (2/04/2009)
#


include("compat.inc");

if(description)
{
 script_id(11185);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2002-2300");
 script_bugtraq_id(6297);
 script_osvdb_id(13576, 17618);

 script_name(english:"3Com NBX ftpd CEL Command Remote Overflow (1)");
	     
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the remote FTP server is a version of VxWorks
ftpd between 5.4 and 5.4.2.  Such versions are known to be affected by
a buffer overflow that can be triggered with an overly-long 'CEL'
command.  This problem is similar to the 'aix ftpd' overflow but on
embedded VxWorks-based systems like the 3Com NBX IP phone call manager
and seems to cause the server to crash." );
 script_set_attribute(attribute:"see_also", value:"http://www.secnap.net/security/nbx001.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/344" );
 script_set_attribute(attribute:"solution", value:
"If you are using an embedded VxWorks product, please contact the OEM
vendor and reference WindRiver field patch TSR 296292.  If this is the
3Com NBX IP Phone call manager, contact 3Com." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/12/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/02");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks if the vxworks ftpd can be buffer overflowed");
 script_category(ACT_GATHER_INFO); 
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2002-2016 Michael Scheidell");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 script_require_keys("ftp/vxftpd");
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);


banner = get_ftp_banner(port: port);
if (! banner) exit(1);

#VxWorks (5.4) FTP server ready
#220 VxWorks (5.4.2) FTP server ready
#above affected,
# below MIGHT be ok:
#220 VxWorks FTP server (VxWorks 5.4.2) ready
# and thus the banner check may be valid

# for some reason, escaping the parens causes a login failure here
#                             (5.4) or (5.4.[1-2])
 if(egrep(pattern:".*xWorks .(5\.4.|5\.4\.[1-2])[^0-9].*FTP",
   	 string:banner)){
  	 security_hole(port);
	 } 
