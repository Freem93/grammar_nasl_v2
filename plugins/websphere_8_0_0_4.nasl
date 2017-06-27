#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61459);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/01/07 15:01:56 $");

  script_cve_id(
    "CVE-2012-2159",
    "CVE-2012-2161",
    "CVE-2012-2170",
    "CVE-2012-2190",
    "CVE-2012-2191",
    "CVE-2012-3293"
  );
  script_bugtraq_id(53755, 53884, 54051, 54743, 54819, 55149, 55185);
  script_osvdb_id(82477, 82711, 82754, 83018, 84468, 84474, 84918);

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 4 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote application server may be affected by multiple 
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM WebSphere Application Server 8.0 before Fix Pack 4 appears to be
running on the remote host and is potentially affected by the
following vulnerabilities :

  - An input validation error exists related to the 'Eclipse
    Help System' that can allow arbitrary redirect responses
    to HTTP requests. (CVE-2012-2159, CVE-2012-2161,
    PM62795)

  - An error exists related to 'Application Snoop Servlet'
    and missing access controls. This error can allow
    sensitive information to be disclosed. Note that
    exploiting this issue requires that the default
    'Application Snoop Servlet' be installed and running.
    (CVE-2012-2170, PM56183)

  - Several errors exist related to SSL/TLS that can allow
    an attacker to carry out denial of service attacks 
    against the application. (CVE-2012-2190, CVE-2012-2191, 
    PM66218)

  - Unspecified cross-site scripting issues exist related to
    the administrative console. (CVE-2012-3293, PM60839)"
  );
  # Security Bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21606096");
  # 8.0.0.4 security fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27022958#8004");
  script_set_attribute(
    attribute:"solution", 
    value:"Apply Fix Pack 4 for version 8.0 (8.0.0.4) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/09");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);

version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 4)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Version source    : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.4' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
