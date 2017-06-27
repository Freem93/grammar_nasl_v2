#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14371);
 script_version("$Revision: 1.20 $");

 script_cve_id("CVE-2003-1327");
 script_bugtraq_id(8668);
 script_osvdb_id(2594);
 
 script_name(english:"WU-FTPD MAIL_ADMIN Function Remote Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"Th remote Wu-FTPD server fails to properly check bounds on a pathname
when Wu-Ftpd is compiled with MAIL_ADMIN enabled resulting in a buffer
overflow.  With a specially crafted request, an attacker can possibly
execute arbitrary code as the user Wu-Ftpd runs as (usually root)
resulting in a loss of integrity, and/or availability. 

It should be noted that this vulnerability is not present within the
default installation of Wu-Ftpd. 

The server must be configured using the 'MAIL_ADMIN' option to notify
an administrator when a file has been uploaded. 

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Sep/336");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wu-FTPd 2.6.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
		
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/09/22");
 script_cvs_date("$Date: 2016/11/01 19:59:57 $");
script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 
 script_summary(english:"Checks the banner of the remote wu-ftpd server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#
include("ftp_func.inc");
include("backport.inc");
include("global_settings.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_ftp_port(default: 21);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if (! banner) exit(1);
if(egrep(pattern:".*(wu|wuftpd)-2\.6\.[012].*", string:banner)) security_hole(port);

