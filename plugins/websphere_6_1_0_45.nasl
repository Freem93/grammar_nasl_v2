#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62394);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2012-2170",
    "CVE-2012-2190",
    "CVE-2012-2191",
    "CVE-2012-3293",
    "CVE-2012-3304",
    "CVE-2012-3305",
    "CVE-2012-3306",
    "CVE-2012-3311",
    "CVE-2012-3325"
  );
  script_bugtraq_id(
    53755,
    54743,
    55149,
    55185,
    55309,
    55671,
    55678
  );
  script_osvdb_id(
    82477,
    84468,
    84474,
    84918,
    85025,
    85732,
    85733,
    85734,
    85735
  );

  script_name(english:"IBM WebSphere Application Server 6.1 < Fix Pack 45 Multiple Vulnerabilities");
  script_summary(english:"Reads the version number from the SOAP port");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote application server may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"IBM WebSphere Application Server 6.1 before Fix Pack 45 appears to be
running on the remote host.  As such, it is potentially affected by
the following vulnerabilities :

  - An error exists related to 'Application Snoop Servlet'
    and missing access controls. This error can allow
    sensitive information to be disclosed. Note that
    exploiting this issue requires that the default
    'Application Snoop Servlet' be installed and running.
    (CVE-2012-2170, PM56183)

  - Several errors exist related to SSL/TLS that can allow
    an attacker to carry out denial of service attacks
    against the application. (CVE-2012-2190, CVE-2012-2191,
    PM66218)

  - Unspecified cross-site scripting issues exist related to
    the administrative console. (CVE-2012-3293, PM60839)

  - An unspecified error in the 'ISC Console' can allow a
    remote attacker to take over a valid user's session.
    (CVE-2012-3304, PM54356)

  - An unspecified directory traversal error exists that
    can allow remote attackers to overwrite files outside
    the application's deployment directory. (CVE-2012-3305,
    PM62467)

  - When multi-domain support is enabled, the application
    does not properly purge passwords from the
    authentication cache. (CVE-2012-3306, PM66514)

  - An error exists related to 'Federated Repositories',
    'IIOP' connections, 'CBIND' checking and 'Optimized
    Local Adapters' that can allow a remote attacker to
    bypass security restrictions. Note that this issue
    affects the application when running on z/OS.
    (CVE-2012-3311, PM61388)

  - The fix contained in PM44303 contains an error that
    can allow an authenticated attacker to bypass security
    restrictions and gain administrative access to the
    application. (CVE-2012-3325, PM71296)"
  );
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg21404665");
  script_set_attribute(attribute:"see_also",value:"http://www-01.ibm.com/support/docview.wss?uid=swg27009778");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/potential_security_exposure_from_ibm_websphere_application_server_impacts_rational_application_developer_cve_2012_33256?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bad06dcb");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_directory_server_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33253?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?58770565");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_federated_identity_manager_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33252?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80adf3bd");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_tivoli_access_manager_for_e_business_potential_security_exposure_with_ibm_websphere_application_server_apar_pm44303_cve_2012_33253?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcf28d02");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21618044");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21620517");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21620518");
  # 6.1.0.45 security bulletin
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21611311");
  # 6.1.0.45 downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24033269");
  # 6.1.0.45 fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951#61045");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 45 (6.1.0.45) or
later. 

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("websphere_detect.nasl");
  script_require_ports("Services/www", 8880, 8881);
  script_require_keys("www/WebSphere");

  exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8880, embedded:0);


version = get_kb_item_or_exit("www/WebSphere/"+port+"/version");
if (version =~ "^[0-9]+(\.[0-9]+)?$")
  exit(1, "Failed to extract a granular version from the IBM WebSphere Application Server instance listening on port " + port + ".");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 45)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.45' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
