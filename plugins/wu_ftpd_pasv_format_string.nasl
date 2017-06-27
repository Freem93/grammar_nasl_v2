#
# (C) Tenable Network Security, Inc.
#

# Affected: wu-ftpd up to 2.6.1

include("compat.inc");

if (description)
{
 script_id(11331);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2014/05/27 00:36:24 $");

 script_cve_id("CVE-2001-0187");
 script_bugtraq_id(2296);
 script_osvdb_id(1744);
 script_xref(name:"CERT", value:"639760");

 script_name(english:"WU-FTPD Debug Mode Client Hostname Remote Format String");
 script_summary(english:"Checks the remote ftpd version");

 script_set_attribute(attribute:"synopsis", value:"The remote FTP server has a format string vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote WU-FTPd server, according to its version number, is
vulnerable to a format string attack when running in debug mode.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?859aecba");
 script_set_attribute(attribute:"solution", value:"Upgrade to WU-FTPD version 2.6.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/01/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"FTP");

 script_copyright(english:"This script is Copyright (C) 2003-2014 Tenable Network Security, Inc.");

 script_dependencie("ftpserver_detect_type_nd_version.nasl", "ftp_anonymous.nasl");
 script_require_keys("ftp/wuftpd", "Settings/ParanoidReport");
 script_require_ports("Services/ftp", 21);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ftp_func.inc");
include("backport.inc");


if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_kb_item("Services/ftp");
if(!port) port = 21;
if (!get_tcp_port_state(port)) exit(0);

banner = get_backport_banner(banner:get_ftp_banner(port: port));
if (banner)
{
  banner = tolower(banner);
  if(egrep(pattern:"(wu|wuftpd)-((1\..*)|2\.([0-5]\..*|6\.[0-1]))", string:banner))
  	security_hole(port);
}
