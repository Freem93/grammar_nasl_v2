#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45416);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id("CVE-2007-1608");
  script_bugtraq_id(23086);
  script_osvdb_id(34484);
  script_xref(name:"Secunia", value:"24552");

  script_name(english:"IBM WebSphere Application Server 6.0 < 6.0.2.19 HTTP Response Splitting");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by an HTTP response
splitting vulnerability.");
 script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0.x before Fix Pack 19 appears to
be running on the remote host.  Such versions are reportedly affected
by an HTTP response splitting vulnerability because the application
fails to properly sanitize user-supplied data to an unspecified
parameter and script.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27006876#60219");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PK39732");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 19 (6.0.2.19) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");

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


port = get_http_port(default:8880);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  (ver[0] == 6 && ver[1] == 0 && ver[2] < 2) ||
  (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 19)
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0.2.19' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
