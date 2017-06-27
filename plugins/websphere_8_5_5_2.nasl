#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74235);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2013-5372",
    "CVE-2013-5780",
    "CVE-2013-5803",
    "CVE-2013-6323",
    "CVE-2013-6325",
    "CVE-2013-6329",
    "CVE-2013-6438",
    "CVE-2013-6725",
    "CVE-2013-6738",
    "CVE-2013-6747",
    "CVE-2014-0050",
    "CVE-2014-0823",
    "CVE-2014-0857",
    "CVE-2014-0859",
    "CVE-2014-0891",
    "CVE-2014-0896"
  );
  script_bugtraq_id(
    63082,
    63115,
    63224,
    64249,
    65096,
    65099,
    65156,
    65400,
    66303,
    67051,
    67327,
    67328,
    67329,
    67335,
    67579,
    67720
  );
  script_osvdb_id(
    98562,
    98569,
    98716,
    100864,
    102119,
    102120,
    102556,
    102945,
    104579,
    104580,
    106246,
    106515,
    106516,
    106517,
    106518,
    106519
  );

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 8.5.5.2 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server may be affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 8.5 prior to Fix Pack 8.5.5.2 appears
to be running on the remote host and is, therefore, potentially
affected by the following vulnerabilities :

  - Numerous errors exist related to the included IBM SDK
    for Java (based on the Oracle JDK) that could allow
    denial of service attacks and information disclosure.
    (CVE-2013-5372, CVE-2013-5780, CVE-2013-5803)

  - User input validation errors exist related to the
    Administrative console and the Oauth component that
    could allow cross-site scripting attacks.
    (CVE-2013-6725 / PM98132, CVE-2013-6323 / PI04777,
    CVE-2013-6738 / PI05661)

  - An error exists due to a failure to properly
    handle by web services endpoint requests that
    could allow denial of service attacks.
    (CVE-2013-6325 / PM99450, PI08267)

  - An error exists in the included IBM Global Security
    Kit related to SSL handling that could allow denial
    of service attacks. (CVE-2013-6329 / PI05309)

  - A flaw exists with the 'mod_dav' module that is caused
    when tracking the length of CDATA that has leading
    white space. A remote attacker with a specially crafted
    DAV WRITE request can cause the service to stop
    responding. (CVE-2013-6438 / PI09345)

  - An error exists in the included IBM Global Security
    Kit related to malformed X.509 certificate chain
    handling that could allow denial of service attacks.
    (CVE-2013-6747 / PI09443)

  - An error exists in the included Apache Tomcat version
    related to handling 'Content-Type' HTTP headers and
    multipart requests such as file uploads that could
    allow denial of service attacks. (CVE-2014-0050 /
    PI12648, PI12926)

  - An unspecified error exists that could allow file
    disclosures to remote unauthenticated attackers.
    (CVE-2014-0823 / PI05324)

  - An unspecified error exists related to the
    Administrative console that could allow a security
    bypass. (CVE-2014-0857 / PI07808)

  - An error exists related to a web server plugin and
    retrying failed POST requests that could allow denial
    of service attacks. (CVE-2014-0859 / PI08892)

  - An error exists related to the Proxy and ODR components
    that could allow information disclosure. (CVE-2014-0891
    / PI09786)

  - An unspecified error exists related to the 'Liberty
    Profile' that could allow information disclosure.
    (CVE-2014-0896 / PI10134)");
  # Downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037250");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27036319#8552");
  # Sec bulletin
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21669554");
  # Java JDK items
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21655990");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 8.5.5.2 for version 8.5 (8.5.5.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

if (version !~ "^8\.5([^0-9]|$)") audit(AUDIT_NOT_LISTEN, "IBM WebSphere Application Server 8.5", port);

if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, "IBM WebSphere Application Server", port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 8 &&
  ver[1] == 5 &&
  (
    ver[2] < 5
    ||
    (ver[2] == 5 && ver[3] < 2)
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.5.5.2' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "IBM WebSphere Application Server", port, version);
