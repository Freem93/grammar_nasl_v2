#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11332);
 script_version ("$Revision: 1.16 $");
 script_cve_id("CVE-2001-0935");
 script_osvdb_id(13998);
 
 script_name(english:"WU-FTPD Unspecified Security Issue");
 script_summary(english:"Checks the remote FTPd version");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server has an unspecified remote vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of WU-FTPD running on the remote host has an unspecified
remote vulnerability. This is reportedly due to an unspecified bug in
glob.c discovered by the SuSE security team.

Nessus verified this vulnerability by looking at the banner
of the remote FTP server." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to WU-FTPD version 2.6.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/28");
 script_cvs_date("$Date: 2014/05/24 02:20:54 $");
 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:washington_university:wu-ftpd");
 script_end_attributes();
     
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");
		  
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
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

port = get_ftp_port(default: 21);


banner = get_ftp_banner(port: port);
if (! banner) exit(1);
if(egrep(pattern:".*(wu|wuftpd)-(1\..*|2\.[0-5]\.|2\.6\.0).*", string:banner))
  security_hole(port);
