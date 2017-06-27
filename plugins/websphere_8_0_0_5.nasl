#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64380);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/10 18:05:24 $");

  script_cve_id(
    "CVE-2012-3304",
    "CVE-2012-3305",
    "CVE-2012-3306",
    "CVE-2012-3311",
    "CVE-2012-3325",
    "CVE-2012-3330"
  );
  script_bugtraq_id(55309, 55671, 55678, 56459);
  script_osvdb_id(85025, 85732, 85733, 85734, 85735, 87338);

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 5 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 8.0 before Fix Pack 5 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - An unspecified error exists related to the
    Administrative Console that can allow an attacker to
    hijack sessions. (CVE-2012-3304, PM54356)

  - An unspecified directory traversal error exists that
    can allow remote attackers to overwrite files outside
    the application's deployment directory. (CVE-2012-3305,
    PM62467)

  - When multi-domain support is enabled, the application
    does not properly purge passwords from the
    authentication cache. (CVE-2012-3306, PM66514)

  - An error exists related to Federated Repositories for
    IIOP connections, Optimized Local Adapters and CBIND
    checking that can allow a local attacker to access or
    modify arbitrary files. Note this issue only affects the
    application when hosted on z/OS. (CVE-2012-3311,
    PM61388)

  - The fix contained in PM44303 contains an error that
    can allow an authenticated attacker to bypass security
    restrictions and gain administrative access to the
    application. (CVE-2012-3325, PM71296)

  - A request validation error exists related to the proxy
    server component that could allow a remote attacker to
    cause the proxy status to be reported as disabled, thus
    denying applications access to the proxy.
    (CVE-2012-3330, PM71319)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033754");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27022958#8005");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21615074");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 5 for version 8.0 (8.0.0.5) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

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
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server " + version + " instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 5)
{
  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report = 
      '\n  Version source    : ' + source + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.5' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
