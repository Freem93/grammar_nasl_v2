#
# This script was written by Audun Larsen <larsen@xqus.com>
#
# Changes by Tenable:
# - Revised plugin title (2/03/2009)

include("compat.inc");

if(description)
{
 script_id(12075);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/15 19:41:08 $");

 script_cve_id("CVE-2004-0325");
 script_bugtraq_id(9702);
 script_osvdb_id(4058);

 script_name(english:"TYPSoft FTP Server 1.10 Invalid Path Request DoS");
 script_summary(english:"Checks for version of TYPSoft FTP server");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP service has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"The remote host appears to be running TYPSoft FTP server.  According
to its banner, this version of the software has a denial of service
vulnerability that can lead to complete exhaustion of CPU resources."
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Feb/612"
 );
 script_set_attribute(
   attribute:"solution",
   value:"There is no known solution at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/23");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Audun Larsen");
 script_family(english:"FTP");

 script_dependencie("ftpserver_detect_type_nd_version.nasl");
 script_require_keys("ftp/typsoftftp");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default:21);

banner = get_ftp_banner(port:port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (
  egrep(pattern:".*TYPSoft FTP Server (0\.|1\.[0-9][^0-9]|1\.10[^0-9])", string:banner)
) security_hole(port);

