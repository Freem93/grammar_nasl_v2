#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(71229);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/13 21:07:14 $");

  script_cve_id(
    "CVE-2012-2098",
    "CVE-2013-0460",
    "CVE-2013-0464",
    "CVE-2013-0467",
    "CVE-2013-0599",
    "CVE-2013-1862",
    "CVE-2013-1896",
    "CVE-2013-3029",
    "CVE-2013-4004",
    "CVE-2013-4005",
    "CVE-2013-4006",
    "CVE-2013-4052",
    "CVE-2013-4053",
    "CVE-2013-5414",
    "CVE-2013-5417",
    "CVE-2013-5418",
    "CVE-2013-5425"
  );
  script_bugtraq_id(
    53676,
    57510,
    58000,
    59826,
    60107,
    60246,
    61129,
    61901,
    61935,
    61937,
    62336,
    62338,
    63700,
    63778,
    63780,
    63781,
    63786
  );
  script_osvdb_id(
    82161,
    89518,
    90318,
    93366,
    93601,
    93760,
    94748,
    95498,
    96507,
    96508,
    97233,
    97234,
    99761,
    99762,
    99763,
    99764,
    99765
  );

  script_name(english:"IBM WebSphere Application Server 8.5 < Fix Pack 8.5.5.1 Multiple Vulnerabilities");
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
"IBM WebSphere Application Server 8.5 before Fix Pack 8.5.5.1 appears to
be running on the remote host and is, therefore, potentially affected by
the following vulnerabilities :

  - A flaw exists related to Apache Ant and file
    compression that could lead to denial of service
    conditions. (CVE-2012-2098 / PM90088)

  - Unspecified errors exist related to the administration
    console that could allow cross-site scripting attacks.
    (CVE-2013-0460 / PM72275, CVE-2013-5418 / PM96477,
    CVE-2013-5425 / PM93828)

  - Multiple errors exist related to the IBM Eclipse Help
    System that could allow cross-site scripting attacks
    and information disclosure attacks. (CVE-2013-0464,
    CVE-2013-0467, CVE-2013-0599 / PM89893)

  - An input validation flaw exists in the optional
    'mod_rewrite' module in the included IBM HTTP Server
    that could allow arbitrary command execution via
    HTTP requests containing certain escape sequences.
    (CVE-2013-1862 / PM87808)

  - A flaw exists related to the optional 'mod_dav'
    module in the included IBM HTTP Server that could
    allow denial of service conditions.
    (CVE-2013-1896 / PM89996)

  - A user-supplied input validation error exists that could
    allow cross-site request forgery (CSRF) attacks to be
    carried out. (CVE-2013-3029 / PM88746)

  - User-supplied input validation errors exist related to
    the administrative console that could allow cross-site
    scripting attacks.
    (CVE-2013-4004 / PM81571, CVE-2013-4005 / PM88208)

  - An unspecified permissions error exists that could
    allow a local attacker to obtain sensitive information.
    Note this issue only affects the 'Liberty Profile'.
    (CVE-2013-4006 / PM90472)

  - An input validation error exists related to the UDDI
    Administrative console that could allow cross-site
    scripting attacks. (CVE-2013-4052 / PM91892)

  - An attacker may gain elevated privileges because of
    improper certificate checks. WS-Security and XML Digital
    Signatures must be enabled. (CVE-2013-4053 / PM90949)

  - An error exists related to incorrect Administration
    Security roles and migrations from version 6.1.
    (CVE-2013-5414 / PM92313)

  - Unspecified input validation errors exist that could
    allow cross-site scripting attacks. (CVE-2013-5417 /
    PM93323 and PM93944)"
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_potential_security_exposure_in_ibm_http_server_cve_2013_1862_pm87808?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?187690fd");
  # Fix list
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27036319#8551");
  # Sec bulletin
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?&uid=swg21651880");
  script_set_attribute(attribute:"solution", value:"Apply Fix Pack 8.5.5.1 for version 8.5 (8.5.5.0) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/05");

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
source = get_kb_item_or_exit("www/WebSphere/"+port+"/source");

if (version !~ "^8\.5([^0-9]|$)") audit(AUDIT_NOT_LISTEN, "IBM WebSphere Application Server 8.5", port);

if (version =~ "^[0-9]+(\.[0-9]+)?$") audit(AUDIT_VER_NOT_GRANULAR, "IBM WebSphere Application Server", port, version);

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

if (
  ver[0] == 8 &&
  ver[1] == 5 &&
  (
    ver[2] < 5
    ||
    (ver[2] == 5 && ver[3] < 1)
  )
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.5.5.1' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "WebSphere", port, version);
