#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45429);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2012/05/04 17:11:07 $");

  script_cve_id("CVE-2010-0768", "CVE-2010-0769", "CVE-2010-0770", "CVE-2010-0774", "CVE-2010-0775");
  script_bugtraq_id(39051, 39056, 40322, 40325);
  script_osvdb_id(63307, 63308, 63480, 64741, 64742);
  script_xref(name:"Secunia", value:"39140");
  script_xref(name:"Secunia", value:"39838");

  script_name(english:"IBM WebSphere Application Server 6.0 < 6.0.2.41 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0 before Fix Pack 41 for 6.0.2
appears to be running on the remote host.  As such, it is reportedly
affected by multiple vulnerabilities :

  - An unspecified cross-site scripting vulnerability in the
    Administration Console. (PK97376)

  - An error when defining a wsadmin scripting 
    'J2CConnectionFactory' object results in passwords being
    stored unencrypted in the resources.xml file. (PK95089)

  - An error related to the ORB ListenerThread could allow
    remote, authenticated users to cause a denial of service.
    (PK93653)

  - WS-Security processing problems with PKIPath and
    PKCS#7 tokens could lead to a security bypass
    vulnerability. (PK96427)

  - An OutOfMemory condition related to the
    Deployment Manager and nodeagent cause lead to a
    denial of service. (PM05663)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27004980");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27006876");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 41 for version 6.0.2 (6.0.2.41) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");

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

if (
  (ver[0] == 6 && ver[1] == 0 && ver[2] < 2) ||
  (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 41)
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0.2.41' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
