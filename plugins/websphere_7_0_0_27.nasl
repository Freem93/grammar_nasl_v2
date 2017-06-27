#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64097);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2012-3330",
    "CVE-2012-4853",
    "CVE-2013-0458",
    "CVE-2013-0459",
    "CVE-2013-0460",
    "CVE-2013-0461"
  );
  script_bugtraq_id(56458, 56459, 57508, 57509, 57510, 57512);
  script_osvdb_id(87338, 87339, 89514, 89515, 89517, 89518);

  script_name(english:"IBM WebSphere Application Server 7.0 < Fix Pack 27 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 7.0 before Fix Pack 27 appears to be
running on the remote host.  It is, therefore, potentially affected by
the following vulnerabilities :

  - A request validation error exists related to the proxy
    server component that could allow a remote attacker to
    cause the proxy status to be reported as disabled, thus
    denying applications access to the proxy.
    (CVE-2012-3330, PM71319)

  - A user-supplied input validation error exists that could
    allow cross-site request forgery (CSRF) attacks to be
    carried out. (CVE-2012-4853, PM62920)

  - Unspecified errors exist related to the administration
    console that could allow cross-site scripting attacks.
    (CVE-2013-0458, CVE-2013-0459, CVE-2013-0460, PM71139,
    PM72536, PM72275)

  - An unspecified error exists related to the
    administration console for 'virtual member manager'
    (VMM) that can allow cross-site scripting.
    (CVE-2013-0461, PM71389)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_vulnerabilities_fixed_in_ibm_websphere_application_server_7_0_0_2785?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8df3590");
  # http://www-01.ibm.com/support/docview.wss?uid=swg24033882
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85335f50");
  # http://www-01.ibm.com/support/docview.wss?uid=swg27014463#70027
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6249ee05");
  # https://www-304.ibm.com/support/docview.wss?uid=swg21622444
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ae80ba2");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 27 (7.0.0.27) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, contact the vendor for more information as IBM
currently has not a published fix pack 27 for that.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");

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
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server " + version + " instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 7 && ver[1] == 0 && ver[2] == 0 && ver[3] < 27)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 7.0.0.27' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
