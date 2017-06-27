#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(47112);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2010-0774",
    "CVE-2010-0775",
    "CVE-2010-0776",
    "CVE-2010-0777",
    "CVE-2010-0778",
    "CVE-2010-0779",
    "CVE-2010-1650",
    "CVE-2010-1651",
    "CVE-2010-2324",
    "CVE-2010-2325",
    "CVE-2010-2326",
    "CVE-2010-2327",
    "CVE-2010-2328"
  );
  script_bugtraq_id(
    40277,
    40321,
    40322,
    40325,
    40694,
    40699,
    41081,
    41084,
    41085,
    41091,
    41148,
    41149
  );
  script_osvdb_id(
    64249,
    64250,
    64721,
    64740,
    64741,
    64742,
    65437,
    65438,
    65439,
    65650,
    65651,
    65652,
    65798,
    65799
  );
  script_xref(name:"Secunia", value:"39838");
  script_xref(name:"Secunia", value:"40096");

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 11 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 7.0 before Fix Pack 11 appears to be
running on the remote host.  As such, it is reportedly affected by the
following vulnerabilities :

  - WS-Security processing problems with PKIPath and
    PKCS#7 tokens could lead to a security bypass
    vulnerability. (PK96427)

  - An OutOfMemory condition related to the
    Deployment Manager and nodeagent could lead to a
    denial of service. (PM05663)

  - The Web Container does not properly handle long
    filenames, which may cause it to respond with the
    incorrect file, resulting in the disclosure of
    potentially sensitive information. (PM06111)

  - An information disclosure vulnerability exists when the
    '-trace' option (aka debugging mode) is enabled since
    WAS executes debugging statements that print string
    representations of unspecified objects. (PM06839)

  - An error occurs when the Web Contained calls
    response.sendRedirect with a Transfer-Encoding:
    chunked, which could cause a denial of service.
    (PM08760)

  - An information disclosure vulnerability in SIP logging
    could allow a local, authenticated attacker to gain
    access to sensitive information. (PM08892)

  - A possible NullPointerException when handling large
    chunked gzip encoded data. (PM08894)

  - A possible link injection vulnerability. (PM09250)

  - The web server can fail during an upload over SSL that
    is larger than 2 GB. (PM10270)

  - Administration console sensitive information might appear in
    addNode.log when -trace option enabled. (PM10684)

  - Cross-site scripting and URL injection vulnerability
    in admin console. (PM11778)");

  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27014463#70011");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 11 (7.0.0.11) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

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

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 11)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.11' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
