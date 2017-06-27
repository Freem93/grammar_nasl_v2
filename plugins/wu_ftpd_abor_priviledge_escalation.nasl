#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14301);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-1999-1326");
 script_osvdb_id(8718);
 
 script_name(english:"WU-FTPD ABOR Command Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server seems to be vulnerable to a remote privilege
escalation." );
 script_set_attribute(attribute:"description", value:
"The version of WU-FTPD running on the remote host contains a flaw that
may allow a malicious user to gain access to unauthorized privileges. 

Specifically, there is a flaw in the way that the server handles
an ABOR command after a data connection has been closed.  The 
flaw is within the dologout() function and proper exploitation
will give the remote attacker the ability to execute arbitrary 
code as the 'root' user.

This flaw may lead to a loss of confidentiality and/or integrity.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jan/11");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1997/Jan/18");
 script_set_attribute(attribute:"solution", value:
"Upgrade to Wu-FTPd 2.4.2 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
		
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/01/04");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");
script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 
 script_summary(english:"Checks the banner of the remote WU-FTPD server");
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
include("global_settings.inc");
include("ftp_func.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if (! banner) exit(1);

if(egrep(pattern:".*(wu|wuftpd)-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_warning(port);
