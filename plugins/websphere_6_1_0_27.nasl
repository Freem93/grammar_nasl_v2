#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(41057);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/11/29 20:13:37 $");

  script_cve_id(
    "CVE-2009-0023",
    "CVE-2009-1955",
    "CVE-2009-1956",
    "CVE-2009-2091",
    "CVE-2009-2742",
    "CVE-2009-2743",
    "CVE-2009-2744",
    "CVE-2009-3106"
  );
  script_bugtraq_id(35221, 35251, 35253, 36157, 36455, 36456, 36458);
  script_osvdb_id(
    55057,
    55058,
    55059,
    57037,
    57884,
    58324,
    58364,
    58365
  );

  script_name(english:"IBM WebSphere Application Server < 6.1.0.27 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 27 appears to be
running on the remote host.  As such, it is reportedly affected by
multiple vulnerabilities :

  - The Eclipse help system included with WebSphere
    Application Server is affected by a cross-site
    scripting vulnerability. (PK78917)

  - It may be possible to bypass security restrictions
    using a specially crafted HTTP HEAD method. (PK83258)

  - New applications deployed in WebSphere Application
    Server for z/OS prior to 1.8 are saved on the file
    system with insecure privileges resulting in
    disclosure of sensitive information. (PK83308)

  - If JAAS-J2C Authentication Data is configured using
    wsadmin scripts, the password value may appear in
    FFDC logs. (PK86137)

  - Apache APR-util is affected by a denial of service
    issue. (PK88341)

  - Due to an error in expat XML parser, APR-util is
    affected by a denial of service issue. (PK88342)

  - It may be possible to trigger a denial of service
    attack due to errors in Fix Packs 6.1.0.23 and
    6.1.0.25. (PK91709)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK91241");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24023947");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951#61027");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 27 (6.1.0.27) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189, 264, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/23");

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

port = get_http_port(default:8880);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 27)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.27' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
