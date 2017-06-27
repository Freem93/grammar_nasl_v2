#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45420);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2011/12/07 02:22:17 $");

  script_cve_id("CVE-2007-1944", "CVE-2007-1945", "CVE-2007-3262", "CVE-2007-3263");
  script_bugtraq_id(23459);
  script_osvdb_id(41604, 41605, 41613, 41614);
  script_xref(name:"Secunia", value:"24852");
  script_xref(name:"Secunia", value:"25704");

  script_name(english:"IBM WebSphere Application Server 6.1 < 6.1.0.7 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 7 appears to be
running on the remote host.  As such, it is reportedly affected by the
following vulnerabilities :

  - An unspecified denial of service vulnerability in the
    Java Message Service (JMS).

  - An unspecified vulnerability in the Servlet Engine/
    Web Container. (PK36447)

  - An unspecified vulnerability in the Default Messaging
    component could lead to a denial of service. 

  - An unspecified vulnerability in the Default Messaging
    component which has unknown impact and attack vectors.");

  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg27007951#6107");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 7 (6.1.0.7) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2011 Tenable Network Security, Inc.");

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

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 7)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.7' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
