
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51510);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2010-0783",
    "CVE-2010-0785",
    "CVE-2011-0315",
    "CVE-2011-0316",
    "CVE-2011-1310",
    "CVE-2011-1313",
    "CVE-2011-1319",
    "CVE-2011-1320"
  );
  script_bugtraq_id(43875, 44670, 45800, 45802);
  script_osvdb_id(
    68537,
    69007,
    70386,
    70387,
    73347,
    73350,
    73379,
    73381
  );
  script_xref(name:"Secunia", value:"42136");

  script_name(english:"IBM WebSphere Application Server 6.1 < 6.1.0.35 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 35 appears to be
running on the remote host.  As such, it is reportedly affected by
multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability
    exists in the Administration Console. (PM14251)

  - A double free error in BBOOORBR control block could
    trigger a denial of service condition. (PM17170)

  - An unspecified cross-site scripting vulnerability
    exists in the web container. (PM18512)

  - It is possible for authenticated users to trigger a DoS
    condition by using Lightweight Third-Party
    Authentication (LTPA) tokens for authentication.
    (PM18644)

  - Sensitive wsadmin command parameters are included in
    trace files, which could result in an information
    disclosure vulnerability. (PM18736)

  - An unspecified cross-site request forgery vulnerability
    exists in the Administration Console. (PM18909)

  - User credentials are not cleared from the cache, even
    after a user has logged out. (PM21536)

  - An unspecified vulnerability could allow improper
    access to console servlets. (PM24372)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61035");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 35 (6.1.0.35) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:FALSE);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 35)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.35' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
