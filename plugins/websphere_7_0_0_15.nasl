#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52615);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/03/02 14:34:38 $");

  script_cve_id(
    "CVE-2011-0315",
    "CVE-2011-0316",
    "CVE-2011-1307",
    "CVE-2011-1308",
    "CVE-2011-1309",
    "CVE-2011-1310",
    "CVE-2011-1311",
    "CVE-2011-1312",
    "CVE-2011-1313",
    "CVE-2011-1314",
    "CVE-2011-1315",
    "CVE-2011-1316",
    "CVE-2011-1317",
    "CVE-2011-1318",
    "CVE-2011-1319",
    "CVE-2011-1320",
    "CVE-2011-1321",
    "CVE-2011-1322"
  );
  script_bugtraq_id(46736);
  script_osvdb_id(
    70386,
    70387,
    71456,
    73341,
    73346,
    73347,
    73348,
    73349,
    73350,
    73352,
    73353,
    73354,
    73355,
    73378,
    73379,
    73381,
    73385,
    73386
  );
  script_xref(name:"Secunia", value:"42938");
  script_xref(name:"Secunia", value:"43211");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 15 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 15 appears to be
running on the remote host.  As such, it is reportedly affected by the
following vulnerabilities :

  - A double free error in BBOOORBR control block could
    trigger a denial of service condition. (PM17170)

  - A cross-site scripting vulnerability exists in the
    web container. (PM18512)

  - It is possible for authenticated users to trigger a DoS
    condition by using Lightweight Third-Party
    Authentication (LTPA) tokens for authentication.
    (PM18644)

  - Sensitive wsadmin command parameters are included in
    trace files, which could result in an information
    disclosure vulnerability. (PM18736)

  - A memory leak in
   'com.ibm.ws.jsp.runtime.WASJSPStrBufferImpl' could
    trigger a DoS condition. (PM19500)

  - It is possible to trigger a DoS condition via SAAJ
    API provided by the WebSphere Web services runtime.
    (PM19534)

  - The Service Integration Bus (SIB) messaging engine is
    affected by a DoS issue. (PM19834)

  - The installer creates a temporary log file directory
    with open '777' permissions. (PM20021)

  - A cross-site scripting vulnerability exists in the
    IVT application.(PM20393)

  - User credentials are not cleared from the cache, even
    after an user has logged out. (PM21536)

  - Trace requests are not handled correctly, which could
    result in an unspecified issue. (PM22860)

  - A memory leak in
    'org.apache.jasper.runtime.JspWriterImpl.response' could
    trigger a denial of service condition. (PM23029)

  - Under certain conditions, SIP proxy may stop processing
    UDP messages, resulting in a DoS condition. (PM23115)

  - Memory leak in the messaging engine could trigger a
    denial of service condition. (PM23626)

  - Improper access is allowed to certain control servlets.
    (PM24372)

  - The AuthCache purge implementation is not able to
    purge a user in AuthCache. (PM24668)

  - Incorrect security role mapping could occur while
    using J2EE 1.4 application. (PM25455)

  - It is possible for Administrator role members to modify
    primary administrative id via the administrative
    console. (PK88606)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM17170");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM18644");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PM19500");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM19534");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PM19834");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PM24668");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PM21536");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PM23115");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PK88606");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27014463#70015");

  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 15 (7.0.0.15) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 15)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.15' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
