#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45422);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2015/06/23 19:16:51 $");

  script_cve_id("CVE-2008-0740", "CVE-2008-7274");
  script_bugtraq_id(27400, 28216, 46449);
  script_osvdb_id(41646, 42878, 72912);
  script_xref(name:"Secunia", value:"29335");

  script_name(english:"IBM WebSphere Application Server < 6.1.0.15 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"IBM WebSphere Application Server 6.1 before Fix Pack 15 appears to be
running on the remote host.  As such, it is reportedly affected by the
following vulnerabilities :

  - There is an as-yet unspecified security exposure in
    wsadmin (PK45726).

  - Sensitive information might appear in plaintext in the
    http_plugin.log file (PK48785).

  - There is an as-yet unspecified potential security
    exposure in the 'PropFilePasswordEncoder' utility
    (PK52709).

  - There is an as-yet unspecified potential security
    exposure with 'serveServletsByClassnameEnabled'
    (PK52059).

  - Sensitive information may appear in plaintext in
    startserver.log (PK53198).

  - If Fix Pack 9 has been installed, attackers can perform
    an internal application hashtable login by either not
    providing a password or providing an empty password
    when the JAAS Login functionality is enabled.
    (PK54565)");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg1PK54565");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg27007951#61015");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 15 (6.1.0.15) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:FALSE);


version = get_kb_item("www/WebSphere/"+port+"/version");
if (isnull(version)) exit(1, "Failed to extract the version from the IBM WebSphere Application Server instance listening on port " + port + ".");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 15)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Source            : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.15' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The WebSphere Application Server "+version+" instance listening on port "+port+" is not affected.");
