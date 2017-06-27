#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(49690);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/09/10 14:14:53 $");

  script_cve_id(
    "CVE-2010-0776",
    "CVE-2010-0777",
    "CVE-2010-0779",
    "CVE-2010-2327"
  );
  script_bugtraq_id(40277, 40321, 41081, 41149);
  script_osvdb_id(64721, 64740, 65439, 65799);

  script_name(english:"IBM WebSphere Application Server 6.0 < 6.0.2.43 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.0 before Fix Pack 43 for 6.0.2
appears to be running on the remote host.  As such, it is reportedly
affected by multiple vulnerabilities :

  - The Web Container does not properly handle long
    filenames, which could cause it to respond with the
    incorrect file, resulting in the disclosure of
    potentially sensitive information. (PM06111)

  - An error occurs when the Web Contained calls
    response.sendRedirect with a Transfer-Encoding chunked, 
    which could cause a denial of service. (PM08760)

  - The web server can fail during an upload over SSL that
    is larger than 2 GB. (PM10270)

  - An unspecified XSS exists in the Administration
    Console. (PM09250)");

  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27004980");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27006876#60243");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 43 for version 6.0.2 (6.0.2.43) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

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
  (ver[0] == 6 && ver[1] == 0 && ver[2] == 2 && ver[3] < 43)
)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.0.2.43' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
