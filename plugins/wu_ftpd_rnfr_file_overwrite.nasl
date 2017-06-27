#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14302);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-1999-0081");
 script_osvdb_id(8717);
 
 script_name(english:"WU-FTPD rnfr File Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has a file overwrite vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPD server seems to be vulnerable to a remote flaw.

This version contains a flaw that may allow a malicious user to overwrite 
arbitrary files.  The issue is triggered when an attacker sends a specially 
formatted rnfr command.  This flaw will allow a remote attacker to overwrite
any file on the system.

*** Nessus solely relied on the banner of the remote server
*** to issue this warning, so it may be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WU-FTPD 2.4.2 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/08/27");
 script_cvs_date("$Date: 2014/05/24 02:20:54 $");
script_set_attribute(attribute:"potential_vulnerability", value:"true");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

		    
 script_summary(english:"Checks the banner of the remote WU-FTPD server");
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/login", "ftp/wuftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);
  
 exit(0);
}

#
# The script code starts here : 
#

include("ftp_func.inc");
include("global_settings.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#login = get_kb_item("ftp/login");
#pass  = get_kb_item("ftp/password");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port: port);
if (! banner ) exit(1);

if(egrep(pattern:".*(wu|wuftpd)-(2\.([0-3]\.|4\.[01])).*", string:banner))
	security_hole(port);

