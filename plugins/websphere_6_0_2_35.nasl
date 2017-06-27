#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38978);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2009-1898", 
    "CVE-2009-1899", 
    "CVE-2009-1900", 
    "CVE-2009-1901"
  );
  script_bugtraq_id(35405);
  script_osvdb_id(55074, 55075, 55076, 55077, 55078);
  script_xref(name:"Secunia", value:"35301");

  script_name(english:"IBM WebSphere Application Server < 6.0.2.35 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0.2 before Fix Pack 35 appears to
be running on the remote host.  As such, it is reportedly affected by
multiple vulnerabilities :

  - Non-standard HTTP methods are allowed. (PK73246)

  - A login using the LPTAToken cookie may result in 
    extending LTPAToken expiration time longer than the
    LTPAToken timeout value. (PK75919)

  - Cross-site scripting vulnerabilities exist in sample
    applications. (PK76720)

  - If the admin console is directly accessed from http, 
    the console fails to redirect the connection to a 
    secure login page. (PK77010)

  - 'wsadmin' is affected by a security exposure. 
    (PK77495)

  - XML digital signature is affected by a security issue.
    (PK80596) 

  - In certain cases, application source files are exposed. 
    (PK81387)

  - Configservice APIs could display sensitive information. 
    (PK84999)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27006876#60235");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 35 (6.0.2.35) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/01");

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

if (
  (ver[0] == 6 && ver[1] == 0 && ver[2] < 2) ||
  (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 35)
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0.2.35' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
