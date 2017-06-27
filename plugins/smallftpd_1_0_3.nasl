#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Changes by Tenable:
# - Revised plugin title, changed family (2/03/2009)
# - Updated to use compat.inc, added CVSS score (11/20/2009)




include("compat.inc");

if (description)
{
 script_id(12072);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2013/04/04 18:53:28 $");

 script_cve_id("CVE-2004-0299");
 script_bugtraq_id(9684, 40180, 48453, 58856);
 script_osvdb_id(4001, 68959);
 script_xref(name:"EDB-ID", value:"15358");

 script_name(english:"smallftpd 1.0.3 Multiple DoS");
 script_summary(english:"Checks for version of smallftpd");

 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host seems to be running a version of Smallftpd that is
1.0.3 or earlier.  Such versions are reportedly affected by denial of
service and directory traversal vulnerabilities.");
 script_set_attribute(attribute:"solution", value:
"Either disable the service or switch to a different FTP server as
Smallftpd has not been updated since 2004.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2004/02/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2013 Audun Larsen");
 script_family(english:"FTP");
 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

soc = open_sock_tcp(port);
if (! soc)  exit(1);

  data = ftp_recv_line(socket:soc);
  if(data)
  {
   if(egrep(pattern:"^220.*smallftpd (0\..*|1\.0\.[0-3]($|[^0-9]))", string:data) )
   {
    security_warning(port);
   }
  }

