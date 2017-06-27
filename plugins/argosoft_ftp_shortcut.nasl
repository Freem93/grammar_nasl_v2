#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15623);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2011/03/11 20:33:08 $");

 script_cve_id("CVE-2004-2672");
 script_bugtraq_id(11589);
 script_osvdb_id(11325);

 script_name(english:"ArGoSoft FTP Server .lnk Shortcut Upload Arbitrary File Manipulation");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an unauthorized access issue." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ArGoSoft FTP Server. 

It is reported that ArGoSoft FTP Server is prone to an attack that
allows link upload.  An attacker, exploiting this flaw, may be able to
have read and write access to any files and directories on the FTP
server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft FTP 1.4.2.2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/01");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Gets the version of the remote ArGoSoft server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("ftp_func.inc");


port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1, "no FTP banner on port "+port+".");

if (
  "ArGoSoft FTP Server" >< banner &&
  egrep(pattern:"^220 ArGoSoft FTP Server.*Version.*\(1\.([0-3]\..*|4\.[0-1]|4\.2\.[0-1])", string:banner)
) security_hole(port);



