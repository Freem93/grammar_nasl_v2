#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(57607);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2011-1359",
    "CVE-2011-1362",
    "CVE-2011-1377",
    "CVE-2011-3192",
    "CVE-2011-5065",
    "CVE-2011-5066"
  );
  script_bugtraq_id(49362, 50310, 51559, 51560);
  script_osvdb_id(74721, 74817, 76563, 76564, 78575, 78601);

  script_name(english:"IBM WebSphere Application Server 6.1 < 6.1.0.41 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 6.1 before Fix Pack 41 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - A cross-site scripting vulnerability via vectors
    related to web messaging. (CVE-2011-5065)

  - A cross-site scripting vulnerability in the Installation
    Verification Test (IVT) in the Install component.
    (CVE-2011-1362)

  - The SibRaRecoverableSiXaResource class in the Default
    Messaging Component does not properly handle a Service
    Integration Bus (SIB) dump operation involving the
    Failure Data Capture (FFDC) introspection code.  This
    can allow local users to obtain sensitive information by
    reading the FFDC log file. (CVE-2011-5066)

  - A directory traversal vulnerability in the
    administration console that allows remote attackers to
    read arbitrary files on the host. (CVE-2011-1359)

  - A potential Denial of Service with malicious range
    requests. (CVE-2011-3192)

  - An unspecified vulnerability in the Web Services
    Security component when enabling WS-Security for a
    JAX-WS application. (CVE-2011-1377)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24031034");

  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 41 (6.1.0.41) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/19");

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

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 41)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.41' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
