#
# (C) Tenable Network Security, Inc.
# 

# Ref:
# From: "intuit e.b." <intuit@linuxmail.org>
# To: bugtraq@securityfocus.com
# Date: Sun, 15 Feb 2004 20:51:45 +0800
# Subject: Xlight ftp server 1.52 RETR bug


include("compat.inc");

if(description)
{
 script_id(12056);
 script_cve_id("CVE-2004-0255", "CVE-2004-0287");
 script_bugtraq_id(9585, 9627, 9668);
 script_osvdb_id(6614, 6722);
 script_version ("$Revision: 1.21 $");
 
 script_name(english:"Xlight FTP Server Multiple Remote Overflows");
 script_summary(english:"Xlight Stack Overflow");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple remote buffer overflow
vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remot ehost is running a verion of the Xlight FTP server earlier
than 1.53. Such versions are reportedly affected by multiple remote
buffer overflow vulnerabilities. An attacker could exploit these flaws
in order to crash the affected service." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Feb/418" );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=107605633904122&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Xlight server 1.53 or later, as this reportedly fixes the
issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
		 
		 
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/05");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 
 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
		  
 script_require_ports("Services/ftp", 21);
 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");

 exit(0);
}

include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);

if(egrep(pattern:"Xlight server v(0\..*|1\.([0-4][0-9]|5[0-2])[^0-9])", string:banner))security_warning(port);
