#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20012);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/15 19:41:08 $");

  script_cve_id("CVE-2005-3294", "CVE-2009-1668", "CVE-2009-4105", "CVE-2012-5329");
  script_bugtraq_id(15104, 34901, 37114, 40181, 51891, 52554);
  script_osvdb_id(19992, 54585, 60658, 80577);
  script_xref(name:"EDB-ID", value:"18469");
  script_xref(name:"EDB-ID", value:"18615");
  script_xref(name:"EDB-ID", value:"8650");
 
  script_name(english:"TYPSoft FTP Server <= 1.10 Multiple DoS");
  script_summary(english:"Checks version in banner.");
 
  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote FTP server is affected by multiple denial of service
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host appears to be using TYPSoft FTP Server, a small FTP
server for Windows. 

According to its banner, the version of TYPSoft FTP Server installed
on the remote host is 1.10 or earlier.  Such versions suffer from
several denial of service vulnerabilities.

A remote attacker, possibly using anonymous access, can cause the
server to stop responding by sending it an 'ABOR' command without any
active file transfer in progress or can crash it by sending any one of
a number of specially crafted FTP commands."
  );
  script_set_attribute(
   attribute:"see_also", 
   value:"http://seclists.org/fulldisclosure/2005/Oct/351"
  );
  script_set_attribute(
   attribute:"see_also", 
   value:"http://www.securityfocus.com/archive/1/508048/30/0/threaded"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Remove the affected service or use another product as TYPSoft is no
longer supported."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value: "2005/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
 
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_keys("ftp/typsoftftp");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("ftp_func.inc");


port = get_ftp_port(default:21);

# If it looks like TYPSoft FTP...
banner = get_ftp_banner(port:port);
if (! banner) exit(1, "No FTP banner on port "+port+".");
if (
  egrep(pattern:"220[ -]TYPSoft FTP", string:banner)
) {
  # There's a problem if the banner reports it's 1.10 or older.
  if (egrep(pattern:"^220[ -]TYPSoft FTP Server (0\.|1\.(0.*|10) )", string:banner))
  {
    security_warning(port);
    exit(0);
  }
}
