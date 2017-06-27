#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68982);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2013-0169",
    "CVE-2013-0482",
    "CVE-2013-0541",
    "CVE-2013-0542",
    "CVE-2013-0543",
    "CVE-2013-0544",
    "CVE-2013-0597",
    "CVE-2013-1768",
    "CVE-2013-2967",
    "CVE-2013-2976",
    "CVE-2013-3029"
  );
  script_bugtraq_id(
    57778,
    59247,
    59248,
    59250,
    59251,
    59650,
    60534,
    60724
  );
  script_osvdb_id(
    89848,
    92711,
    92712,
    92713,
    92714,
    93006,
    94233,
    94743,
    94744,
    94747,
    94748
  );

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 29 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server is potentially affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 7.0 before Fix Pack 29 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - The TLS protocol in the GSKIT component is vulnerable
    to a plaintext recovery attack. (CVE-2013-0169, PM85211)

  - The WS-Security run time contains a flaw that could be
    triggered by a specially crafted SOAP request to execute
    arbitrary code. (CVE-2013-0482, PM76582)

  - A denial of service vulnerability exists, caused by a
    buffer overflow on localOS registry when using WebSphere
    Identity Manager (WIM). (CVE-2013-0541, PM74909)

  - An unspecified cross-site scripting vulnerability exists
    related to the administrative console. (CVE-2013-0542,
    CVE-2013-2967, PM78614, PM81846)

  - A validation flaw exists relating to 'Local OS
    registries' that may allow a remote attacker to bypass
    security. (CVE-2013-0543, PM75582)

  - A directory traversal vulnerability exists in the
    administrative console via the 'PARAMETER' parameter.
    (CVE-2013-0544, PM82468)

  - A flaw exists relating to OAuth that could allow a
    remote attacker to obtain someone else's credentials.
    (CVE-2013-0597, PM85834, PM87131)

  - A flaw exists relating to OpenJPA that is triggered
    during deserialization that may allow a remote attacker
    to write to the file system and potentially execute
    arbitrary code. (CVE-2013-1768, PM86780, PM86786,
    PM86788, PM86791)

  - An information disclosure issue exists relating to
    incorrect caching by the administrative console.
    (CVE-2013-2976, PM79992)

  - A user-supplied input validation error exists that could
    allow cross-site request (CSRF) attacks to be carried
    out. (CVE-2013-3029, PM88746)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_vulnerabilities_fixed_in_ibm_websphere_application_server_7_0_0_29?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0379569f");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21640799");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 29 (7.0.0.29)
or later.

Otherwise, if using embedded WebSphere Application Server packaged
with Tivoli Directory Server, apply the latest recommended eWAS fix
pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 29)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.29' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
