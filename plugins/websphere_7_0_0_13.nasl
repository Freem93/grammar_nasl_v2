#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50561);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2010-0781",
    "CVE-2010-0783",
    "CVE-2010-0784",
    "CVE-2010-0785",
    "CVE-2010-0786",
    "CVE-2010-1632",
    "CVE-2010-3186",
    "CVE-2010-4220"
  );
  script_bugtraq_id(
    40976,
    42801,
    43425,
    43874,
    43875,
    44670,
    44862,
    44875
  );
  script_osvdb_id(
    65697,
    67570,
    68168,
    68536,
    68537,
    69007,
    69204,
    69214
  );
  script_xref(name:"Secunia", value:"40252");
  script_xref(name:"Secunia", value:"40279");
  script_xref(name:"Secunia", value:"41173");
  script_xref(name:"Secunia", value:"41722");
  script_xref(name:"Secunia", value:"42136");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 13 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 13 appears to be
running on the remote host.  As such, it is reportedly affected by the
following vulnerabilities :

  - A cross-site scripting vulnerability exists in the
    administrative console due to improper filtering on
    input values. (PM14251)

  - A cross-site scripting vulnerability exists in the
    Integrated Solution Console due to improper filtering on
    input values. (PM11777)

  - An unspecified cross-site request forgery vulnerability
    exists in the administrative console for WebSphere
    Application Server. (PM18909)

  - An unspecified cross-site scripting vulnerability
    exists in the administrative console for WebSphere
    Application Server for z/OS. (PM17046)

  - An error exists in JAX-WS WS-Security, which mishandles
    timestamps in the WS-SecurityPolicy specification.
    (PM16014)

  - An error exists in the JAX-WS API, which allows an
    attacker to cause a denial of service by sending a
    specially crafted JAX-WS request. The server will begin
    sending corrupt data to its clients. (PM13777)

  - Apache Axis2/Java, used by WebSphere, is vulnerable to
    denial of service and information disclosure attacks due
    to an error in its XML DTD handling processes. (PM14844)

  - An unspecified error exists in the administration
    console that can cause high CPU usage and denial of
    service when specially crafted URLs are requested.
    (PM11807)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27014463#70013");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/AXIS2-4450");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 13 (7.0.0.13) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache Axis2 File Disclosure");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8880, embedded:0);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 13)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.13' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
