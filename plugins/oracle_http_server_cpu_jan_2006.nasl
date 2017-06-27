#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17729);
  script_cvs_date("$Date: 2016/12/07 20:46:55 $");
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-0286", "CVE-2006-0287");
  script_bugtraq_id(16287);
  script_osvdb_id(22571, 22572);

  script_name(english:"Oracle HTTP Server (January 2006 CPU)");
  script_summary(english:"Checks version in Server response header");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by multiple unspecified
vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"According to its banner, the version of Oracle HTTP Server installed
on the remote host is potentially affected by multiple 
vulnerabilities :

  - An unspecified information disclosure issue exists. 
    (CVE-2006-0286)

  - An unspecified error can allow denial of service
    attacks. (CVE-2006-0287)");

  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2006 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/topics/security/cpujan2006-082403.html");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_http_server_version.nasl");
  script_require_keys("www/oracle", "Settings/PCI_DSS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_http_port(default:80);

# Make sure this is Oracle.
get_kb_item_or_exit("www/"+port+"/oracle");

# Get version information from the KB.
version = get_kb_item_or_exit("www/oracle/"+port+"/version", exit_code:1);
source = get_kb_item_or_exit("www/oracle/"+port+"/source", exit_code:1);

# Check if the remote server is affected.
if (
  # Flag all early versions of both
  #
  # 0.x - 8.x
  (version =~ "^[0-8]\.") ||

  # Application Server
  #
  # 9.0.4.0 - 9.0.4.2
  (version =~ "^9\.0\.4\.[0-2]($|[^0-9])") ||
  # 10.1.2.0.0 - 10.1.2.0.2
  (version =~ "^10\.1\.2\.0\.[0-2]($|[^0-9])")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
} 
else exit(0, "The Oracle Application Server " + version + " install listening on port " + port + " is not affected.");
