#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(16334);
 script_version("$Revision: 1.16 $");

 script_cve_id("CVE-2005-0519", "CVE-2005-0520");
 script_bugtraq_id(12487, 12632);
 script_osvdb_id(13614, 14061);

 script_name(english:"ArGoSoft FTP Server < 1.4.2.8 Multiple .LNK File Handling Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is susceptible to several file access attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the ArGoSoft FTP Server. 

It is reported that ArGoSoft FTP Server allows an attacker to upload
shortcut (.LNK) files via either a 'SITE UNZIP' or 'SITE COPY' command
and gain read and write access to any files and directories on the FTP
server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to ArGoSoft FTP 1.4.2.8 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/08");
 script_cvs_date("$Date: 2011/03/11 20:33:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Gets the version of the remote ArGoSoft server");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

# Check starts here

include("ftp_func.inc");

port = get_ftp_port(default: 21);


banner = get_ftp_banner(port:port);
if (!banner) exit(1, "Cannot read the FTP banner on port "+port+".");

if (
  "ArGoSoft FTP Server" >< banner &&
  egrep(pattern:"^220 ArGoSoft FTP Server.*Version.*\(1\.([0-3]\..*|4\.[0-1]\.|4\.2.\.[0-7][^0-9])", string:banner)
) security_hole(port);
