#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39450);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0899",
    "CVE-2009-0903",
    "CVE-2009-0904",
    "CVE-2009-1174",
    "CVE-2009-1899",
    "CVE-2009-1900",
    "CVE-2009-1901",
    "CVE-2009-2085",
    "CVE-2009-2087",
    "CVE-2009-2088",
    "CVE-2009-2089"
  );
  script_bugtraq_id(
    35405,
    35406,
    35594,
    35741,
    36154,
    36156,
    36158,
    36163
  );
  script_osvdb_id(
    53253,
    55075,
    55076,
    55077,
    55079,
    56161,
    56162,
    57040,
    57041,
    57044,
    57045
  );
  script_xref(name:"Secunia", value:"35491");

  script_name(english:"IBM WebSphere Application Server < 6.1.0.25 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 25 appears to be
running on the remote host.  As such, it is reportedly affected by
multiple vulnerabilities :

  - Non-standard HTTP methods are allowed. (PK73246)

  - An error in Single Sign-on (SSO) with SPNEGO
    implementation could allow a remote attacker
    to bypass security restrictions. (PK77465)

  - 'wsadmin' is affected by a security exposure. (PK77495)

  - Security flag 'isSecurityEnabled' is incorrectly set
    after migrating from VMM. (PK78134)

  - In certain cases sensitive information may appear in
    migration trace. (PK78134)

  - Use of insecure password obfuscation algorithm by Web
    services could result in weaker than expected security
    provided the client module specifies a password in
    ibm-webservicesclient-bind.xmi and target environment
    has custom password encryption enabled. (PK79275)

  - Sensitive information might appear in trace files.
    (PK80337)

  - XML digital signature is affected by a security issue.
    (PK80596)

  - If CSIv2 Security is configured with Identity
    Assertion, it may be possible for a remote
    attacker to bypass security restrictions. (PK83097)

  - IBM Stax XMLStreamWriter may write to an incorrect XML
    file, and hence is susceptible to a XML fuzzing attack.
    (PK84015)

  - Configservice APIs could display sensitive information.
    (PK84999)

  - A security bypass caused by inbound requests that lack
    a SOAPAction or WS-Addressing Action. (PK72138)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27007951#61025");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 25 (6.1.0.25) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(16, 200, 255, 264, 287, 310);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded: 0);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 25)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.25' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
