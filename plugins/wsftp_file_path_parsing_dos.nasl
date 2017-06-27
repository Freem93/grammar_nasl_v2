#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14584);
 script_version("$Revision: 1.27 $");

 script_cve_id("CVE-2004-1643");
 script_bugtraq_id(11065);
 script_osvdb_id(9382);

 script_name(english:"WS_FTP Server Path Parsing Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is prone to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of WS_FTP on the remote host is
vulnerable to a remote denial of service. 

There is an error in the parsing of file paths.  Exploitation of this
flaw may cause a vulnerable system to use a large amount of CPU
resources." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/373420" );
 script_set_attribute(attribute:"see_also", value:"http://www.ipswitch.com/support/ws_ftp-server/releases/wr503.asp" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to WS_FTP Server 5.03 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/31");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Check WS_FTP server version";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 
 script_family(english:"FTP");
 script_dependencie("ftp_anonymous.nasl", "ftpserver_detect_type_nd_version.nasl");
 script_require_ports("Services/ftp", 21);
 
 exit(0);
}

#

include ("ftp_func.inc");

port = get_ftp_port(default: 21);
banner = get_ftp_banner(port:port);
if (! banner) exit(1);

if (egrep(pattern:"WS_FTP Server ([0-4]\.|5\.0\.[0-2][^0-9])", string: banner))
	security_hole(port);
