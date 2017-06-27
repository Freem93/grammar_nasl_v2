#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72062);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2013-0460",
    "CVE-2013-4052",
    "CVE-2013-4053",
    "CVE-2013-5372",
    "CVE-2013-5414",
    "CVE-2013-5417",
    "CVE-2013-5418",
    "CVE-2013-5780",
    "CVE-2013-5803",
    "CVE-2013-6325",
    "CVE-2013-6725"
  );
  script_bugtraq_id(
    57510,
    62336,
    62338,
    63082,
    63115,
    63224,
    63778,
    63780,
    63781,
    65096,
    65099
  );
  script_osvdb_id(
    89518,
    97233,
    97234,
    98562,
    98569,
    98716,
    99761,
    99764,
    99765,
    102119,
    102120
  );

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 8 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 8.0 before Fix Pack 8 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - A CSRF vulnerability exists in IBM WebSphere Application
    Server due to improper validation of portlets in the
    Administrative console. (CVE-2013-0460, PM72275)

  - A privilege escalation vulnerability exists on IBM
    WebSphere Application Servers using WS-Security that are
    configured for XML Digital Signature using trust store.
    (CVE-2013-4053, PM90949, PM91521)

  - An XSS vulnerability exists in IBM WebSphere Application
    Server caused by a failure to sanitize user-supplied
    input in the UDDI Administrative console.
    (CVE-2013-4052, PM91892)

  - A privilege escalation vulnerability exists in IBM
    WebSphere Application Servers that have been migrated
    from version 6.1 or later. (CVE-2013-5414, PM92313)

  - An XSS vulnerability exists in IBM WebSphere Application
    Server due to a failure to sanitize application HTTP
    response data. (CVE-2013-5417, PM93323, PM93944)

  - An XSS vulnerability exists in IBM WebSphere Application
    Server due to a failure to sanitize user-supplied input
    in the Administrative console. (CVE-2013-5418, PM96477)

  - An XSS vulnerability exists in IBM WebSphere Application
    Server due to a failure to sanitize user-supplied input
    in the Administrative console. (CVE-2013-6725, PM98132)

  - A denial of service vulnerability exists in IBM
    WebSphere Application Server due to a failure to
    properly handle requests by a web services endpoint.
    (CVE-2013-6325, PM99450)

  - An information disclosure vulnerability exists in the
    IBM SDK for Java that ships with IBM WebSphere
    Application Server related to JSSE. (CVE-2013-5780)

  - A denial of service vulnerability exists in the IBM SDK
    for Java that ships with IBM WebSphere Application
    Server related to XML. (CVE-2013-5372)

  - A denial of service vulnerability exists in the IBM SDK
    for Java that ships with IBM WebSphere Application
    Server related to JSSE. (CVE-2013-5803)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_vulnerabilites_fixed_in_ibm_websphere_application_server_8_0_0_8?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e351e029");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21661325");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21655990");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 8 for version 8.0 (8.0.0.8) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server " + version + " instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 8)
{
  set_kb_item(name:"www/"+port+"/XSS", value:TRUE);
  set_kb_item(name:"www/"+port+"/XSRF", value:TRUE);
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.8' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port, version);
