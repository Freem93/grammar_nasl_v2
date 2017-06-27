#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59505);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2011-1377",
    "CVE-2012-0193",
    "CVE-2012-0716",
    "CVE-2012-0720"
  );
  script_bugtraq_id(50310, 51441, 52721, 52722);
  script_osvdb_id(76563, 78321, 83123, 83156);

  script_name(english:"IBM WebSphere Application Server 8.0 < Fix Pack 3 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 8.0 before Fix Pack 3 appears to be
running on the remote host and is potentially affected by the
following vulnerabilities :

  - Unspecified cross-site scripting issues exist related to
    the administrative console. (PM52274, PM53132)

  - An issue related to the weak randomization of Java hash
    data structures can allow a remote attacker to cause a
    denial of service with maliciously crafted POST requests.
    (PM53930)

  - An unspecified error exists related to WS-Security
    enabled JAX-RPC applications. (PM45181)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/potential_security_vulnerability_when_using_web_based_applications_on_ibm_websphere_application_server_due_to_java_hashtable_implementation_vulnerability_cve_2012_0193?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca3789f7");
  # PM53930 Alert
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21577532");
  # 8.0.0.3 security fix list
  script_set_attribute(attribute:"see_also", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21589257");
  script_set_attribute(
    attribute:"solution",
    value:"Apply Fix Pack 3 for version 8.0 (8.0.0.3) or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 0 && ver[2] == 0 && ver[3] < 3)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.0.3' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
