#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70022);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/06 17:22:02 $");

  script_cve_id(
    "CVE-2012-2098",
    "CVE-2012-3305",
    "CVE-2012-4853",
    "CVE-2013-0169",
    "CVE-2013-0458",
    "CVE-2013-0459",
    "CVE-2013-0460",
    "CVE-2013-0461",
    "CVE-2013-0462",
    "CVE-2013-0541",
    "CVE-2013-0542",
    "CVE-2013-0543",
    "CVE-2013-0544",
    "CVE-2013-0596",
    "CVE-2013-1768",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-2967",
    "CVE-2013-2976",
    "CVE-2013-3029",
    "CVE-2013-4005",
    "CVE-2013-4052",
    "CVE-2013-4053"
  );
  script_bugtraq_id(
    53676,
    55678,
    56458,
    57508,
    57509,
    57510,
    57512,
    57513,
    57778,
    59247,
    59248,
    59250,
    59251,
    59826,
    60534,
    61129,
    61901,
    61937,
    61940,
    61941,
    62336,
    62338
  );
  script_osvdb_id(
    82161,
    85732,
    87339,
    89514,
    89515,
    89516,
    89517,
    89518,
    89848,
    92711,
    92712,
    92713,
    92714,
    93366,
    94233,
    94743,
    94744,
    94748,
    95498,
    96507,
    97233,
    97234,
    97235
  );

  script_name(english:"IBM WebSphere Application Server 6.1 < Fix Pack 47 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 6.1 before Fix Pack 47 appears to be
running on the remote host.  As such, it is potentially affected by the
following vulnerabilities :

  - A remote attacker can bypass authentication because of
    improper user validation on Linux, Solaris, and HP-UX
    platforms that use a LocalOS registry.
    (CVE-2013-0543, PM75582)

  - A denial of service can be caused by the way Apache
    Ant uses bzip2 to compress files. This can be exploited
    by a local attacker passing specially crafted input.
    (CVE-2012-2098, PM90088)

  - A local attacker can cause a denial of service on
    Windows platforms with a LocalOS registry using
    WebSphere Identity Manager. (CVE-2013-0541, PM74909)

  - Remote attackers can traverse directories by deploying
    a specially crafted application file to overwrite files
    outside of the application deployment directory.
    (CVE-2012-3305, PM62467)

  - The TLS protocol implementation is susceptible to
    plaintext-recovery attacks via statistical analysis of
    timing data for crafted packets. (CVE-2013-0169,
    PM85211)

  - Terminal escape sequences are not properly filtered from
    logs. Remote attackers could execute arbitrary commands
    via an HTTP request containing an escape sequence.
    (CVE-2013-1862, PM87808)

  - Improper validation of user input allows for cross-site
    request forgery. By persuading an authenticated user
    to visit a malicious website, a remote attacker could
    exploit this vulnerability to obtain sensitive
    information. (CVE-2012-4853, CVE-2013-3029, PM62920,
    PM88746)

  - Improper validation of user input in the administrative
    console allows for multiple cross-site scripting
    attacks. (CVE-2013-0458, CVE-2013-0459, CVE-2013-0461,
    CVE-2013-0542, CVE-2013-0596, CVE-2013-2967,
    CVE-2013-4005, CVE-2013-4052, PM71139, PM72536, PM71389,
    PM73445, PM78614, PM81846, PM88208, PM91892)

  - Improper validation of portlets in the administrative
    console allows for cross-site request forgery, which
    could allow an attacker to obtain sensitive information.
    (CVE-2013-0460, PM72275)

  - Remote, authenticated attackers can traverse directories
    on Linux and UNIX systems running the application.
    (CVE-2013-0544, PM82468)

  - A denial of service attack is possible if the optional
    mod_dav module is being used. (CVE-2013-1896, PM89996)

  - Sensitive information can be obtained by a local
    attacker because of incorrect caching by the
    administrative console. (CVE-2013-2976, PM79992)

  - An attacker may gain elevated privileges because of
    improper certificate checks. WS-Security and XML Digital
    Signatures must be enabled. (CVE-2013-4053, PM90949,
    PM91521)

  - Deserialization of a maliciously crafted OpenJPA object
    can result in an executable file being written to the
    file system. WebSphere is NOT vulnerable to this issue
    but the vendor suggests upgrading to be proactive.
    (CVE-2013-1768, PM86780, PM86786, PM86788, PM86791)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_exposure_in_ibm_http_server_cve_2013_1862_pm87808?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?187690fd");
  # 6.1.0.47 security bulletin
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21647522");
  # 6.1.0.47 downloads
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24035508");
  # 6.1.0.47 fix list
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?&uid=swg27004980#ver61");
  script_set_attribute(attribute:"solution", value:
"If using WebSphere Application Server, apply Fix Pack 47 (6.1.0.47)
or later.

Otherwise, if using embedded WebSphere Application Server packaged with
Tivoli Directory Server, apply the latest recommended eWAS fix pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/20");

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

if (ver[0] == 6 && ver[1] == 1 && ver[2] == 0 && ver[3] < 47)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1.0.47' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
