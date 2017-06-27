#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69021);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2013-0169",
    "CVE-2013-0482",
    "CVE-2013-0597",
    "CVE-2013-1768",
    "CVE-2013-2967",
    "CVE-2013-2975",
    "CVE-2013-2976",
    "CVE-2013-3024"
  );
  script_bugtraq_id(57778, 59650, 60534, 60724);
  script_osvdb_id(
    89848,
    93006,
    94233,
    94743,
    94744,
    94745,
    94746,
    94747
  );

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 8.5.5 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 8.5 before Fix Pack 8.5.5 appears to
be running on the remote host and is, therefore, potentially affected by
the following vulnerabilities :

  - The TLS protocol in the GSKIT component is vulnerable
    to a plaintext recovery attack. (CVE-2013-0169, PM85211)

  - The WS-Security run time contains a flaw that could be
    triggered by a specially crafted SOAP request to execute
    arbitrary code. (CVE-2013-0482, PM76582)

  - A flaw exists relating to OAuth that could allow a
    remote attacker to obtain someone else's credentials.
    (CVE-2013-0597, PM85834, PM87131)

  - A flaw exists relating to OpenJPA that is triggered
    during deserialization, which could allow a remote
    attacker to write to the file system and potentially
    execute arbitrary code. (CVE-2013-1768, PM86780,
    PM86786, PM86788, PM86791)

  - An unspecified cross-site scripting vulnerability exists
    related to the administrative console. (CVE-2013-2967,
    PM78614)

  - An unspecified vulnerability exists.  (CVE-2013-2975)

  - An information disclosure vulnerability exists relating
    to incorrect caching by the administrative console.
    (CVE-2013-2976, PM79992)

  - An improper process initialization flaw exists on UNIX
    platforms that could allow a local attacker to execute
    arbitrary commands. (CVE-2013-3024, PM86245)"
  );
  # Fix list
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?&uid=swg21639553");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_vulnerabilities_fixed_in_ibm_websphere_application_server_8_5_5?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa3b02e5");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 8.5.5 for version 8.5 (8.5.5.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

if (version !~ "^8\.5([^0-9]|$)") exit(0, "The version of the IBM WebSphere Application Server instance listening on port "+port+" is "+version+", not 8.5.");

if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 8 && ver[1] == 5 && ver[2] < 5)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.5.5' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
