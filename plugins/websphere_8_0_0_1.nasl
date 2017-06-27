#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(56348);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/29 20:13:38 $");

  script_cve_id(
    "CVE-2011-1355",
    "CVE-2011-1356",
    "CVE-2011-1359",
    "CVE-2011-1368",
    "CVE-2011-1411",
    "CVE-2011-3192"
  );
  script_bugtraq_id(48709, 48710, 48890, 49303, 49362, 49766, 50463);
  script_osvdb_id(73898, 73903, 74167, 74721, 74817, 75718, 76860);

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 1 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote application server may be affected by multiple 
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"IBM WebSphere Application Server 8.0 before Fix Pack 1 appears to be
running on the remote host and is potentially affected by the 
following vulnerabilities :

  - An open redirect vulnerability exists related to the
    'logoutExitPage' parameter. This can allow remote
    attackers to trick users into requesting unintended
    URLs. (PM35701)

  - The administrative console can display a stack trace
    under unspecified circumstances and can disclose
    potentially sensitive information to local users.
    (PM36620)

  - An unspecified error exists that can allow cross-site 
    request forgery attacks. (PM36734)

  - A token verification error exists in the bundled
    OpenSAML library. This error can allow an attacker to
    bypass security controls with an XML signature wrapping
    attack via SOAP messages. (PM43254)

  - A directory traversal attack is possible via unspecified
    parameters in the 'help' servlet. (PM45322)

  - The JavaServer Faces (JSF) application functionality 
    could allow a remote attacker to read files because it
    fails to properly handle requests. (PM45992)

  - The HTTP server contains an error in the 'ByteRange'
    filter and can allow denial of service attacks when
    processing malicious requests. (PM46234)"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.ibm.com/support/docview.wss?uid=swg27022958"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg24030916"
  );
  # PM46234
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www-01.ibm.com/support/docview.wss?uid=swg21512087"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Apply Fix Pack 1 for version 8.0 (8.0.0.1) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 1)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report = 
      '\n  Source            : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
