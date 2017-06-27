#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20754);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-0319");
  script_bugtraq_id(16321);
  script_osvdb_id(22496);

  script_name(english:"Farmers WIFE FTP Server Multiple Command Traversal Arbitrary File Creation");
  script_summary(english:"Checks for directory traversal vulnerability in Farmers WIFE FTP server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote ftp server is affected by a directory traversal flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Farmers WIFE, a commercial
facilities, scheduling, and asset management package targeted at the
media industry. 

The version of Farmers WIFE installed on the remote host includes an
FTP server that reportedly is vulnerable to directory traversal
attacks.  A user can leverage this issue to read and write to files
outside the ftp root.  Note that the application runs with SYSTEM
privileges under Windows." );
 script_set_attribute(attribute:"see_also", value:"http://lists.grok.org.uk/pipermail/full-disclosure/2006-January/041356.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Farmers WIFE 4.4 SP3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/01/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/01/06");
 script_cvs_date("$Date: 2011/03/15 18:34:10 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 22003, "Services/www", 22002);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("ftp_func.inc");


ftp_port = get_ftp_port(default: 22003);
http_port = get_http_port(default:22002);

# Get the initial page.
res = http_get_cache(item:"/", port:http_port, exit_on_fail: 1);

# There's a problem if the version appears to be less than 4.4 SP3.
if (
  "<title>Farmers WIFE Web</title>" >< res &&
  egrep(pattern:">Server Version: ([0-3]\..+|4\.([0-3].*|4( \(sp[0-2]\)))?) &nbsp;", string:res)
) {
  security_warning(ftp_port);
  exit(0);
}
