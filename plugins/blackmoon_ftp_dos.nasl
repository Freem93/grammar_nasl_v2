#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51585);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/19 17:45:33 $");

  script_cve_id("CVE-2011-0507");
  script_bugtraq_id(45814);
  script_osvdb_id(70452);
  script_xref(name:"EDB-ID", value:"15986");
  script_xref(name:"Secunia", value:"42933");

  script_name(english:"BlackMoon FTP Server Denial of Service");
  script_summary(english:"Checks version reported in FTP banner");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP service is vulnerable to a denial of service
attack.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote FTP server
is running a version of BlackMoon FTP Server earlier than 3.1.8.  Such
versions reportedly are affected by a denial of service vulnerability. 
By sending an overly long PORT command, a remote, unauthenticated
attacker may be able to crash the service and deny access to
legitimate users.");

  script_set_attribute(attribute:"see_also", value:"http://www.blackmoonftpserver.com/");
  script_set_attribute(attribute:"solution", value:
"Reports conflict as to whether this issue was fixed in 3.1.7 or
3.1.8. Upgrade to version 3.1.8 or later to be safe.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  exit(0);
}

include("global_settings.inc");
include("ftp_func.inc");
include("misc_func.inc");

# Fetch FTP banner.
port = get_ftp_port(default: 21);

banner = get_ftp_banner(port:port);
if (isnull(banner)) exit(1, "Unable to obtain a banner from the FTP server listening on port "+port+".");

# Check if it's BlackMoon FTP.
if ("BlackMoon FTP Server" >!< banner) exit(0, "The FTP server listening on port "+port+" is not BlackMoon FTP.");

# Parse the version string.
match = eregmatch(string:banner, pattern:"(Version |v)([0-9]+\.[0-9]+\.[0-9]+)");
if (isnull(match)) exit(1, "Could not determine version of BlackMoon FTP listening on port "+port+".");
version = match[2];

# Check if the version string is below the first fixed version.
fixed = "3.1.8";
if (ver_compare(ver:version, fix:fixed) >= 0) exit(0, "Version "+version+" of BlackMoon FTP is listening on port "+port+" and thus not affected.");

# Generate a security report.
if (report_verbosity > 0)
{
  report = 
    '\n  Version source    : ' + banner +
    '\n  Installed version : ' + version + 
    '\n  Fixed version     : ' + fixed + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
