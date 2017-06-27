#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(12060);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-2004-0282");
 script_bugtraq_id(9651);
 script_osvdb_id(6621);

 script_name(english:"Crob FTP Server Connection Saturation Remote DoS");
 script_summary(english:"Crob Remote DoS");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote FTP server has a denial of service vulnerability."
 );
 script_set_attribute(attribute:"description", value:
"According to its version number, the remote Crob FTP server has a
denial of service vulnerability.  Repeatedly connecting and
disconnecting causes the service to crash." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Feb/375"
 );
 script_set_attribute(
   attribute:"solution",
   value:"Upgrade to the latest version of Crob FTP server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/02/12");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_require_ports("Services/ftp", 21);
 script_dependencie("ftpserver_detect_type_nd_version.nasl");

 exit(0);
}

#

include("ftp_func.inc");

port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if ( ! banner ) exit(1);


# 220-Crob FTP Server V3.5.2
#220 Welcome to Crob FTP Server.
if(egrep(pattern:"Crob FTP Server V(3\.([0-4]\..*|5\.[0-2])|[0-2]\..*)", string:banner)) security_warning(port);

