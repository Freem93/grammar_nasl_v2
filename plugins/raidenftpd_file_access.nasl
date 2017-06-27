#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(18225);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-1480");
 script_bugtraq_id(13292);
 script_osvdb_id(15713);

 script_name(english:"RaidenFTPD urlget Command Traversal Arbitrary File Access");

 script_set_attribute(
  attribute:"synopsis",
  value:"The remote FTP server has a directory traversal vulnerability."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is running the RaidenFTPD FTP server.  This version
has a directory traversal vulnerability that could allow an attacker
to read arbitrary files outside of the intended FTP root."
 );
 script_set_attribute(
  attribute:"see_also",
  value:"http://seclists.org/bugtraq/2005/May/23"
 );
 script_set_attribute(
  attribute:"solution",
  value:"Upgrade to RaidenFTPD 2.4 build 2241 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/05/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/05/02");
 script_cvs_date("$Date: 2016/11/17 15:28:26 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();
 
 summary["english"] = "Detects RaidenFTPD Unauthorized File Access";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/login");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");

port = get_ftp_port(default: 21);

login = get_kb_item_or_exit("ftp/login");
password = get_kb_item_or_exit("ftp/password");

banner = get_ftp_banner(port: port);
if ( ! banner ) exit(0);
if (!egrep(pattern:".*RaidenFTPD.*", string:banner))exit(0);


soc = open_sock_tcp(port);
if (! soc) exit(1);

 	     ftp_recv_line(socket:soc);
	     if(ftp_authenticate(socket:soc, user:login, pass:password))
	      {
   		s = string("quote site urlget file:/..\\boot.ini\r\n");
   		send(socket:soc, data:s);
   		r = ftp_recv_line(socket:soc);
		if ("220 site urlget " >< r) security_warning(port);

	      }
ftp_close(socket: soc);
