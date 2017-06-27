#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96177);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/26 16:57:35 $");

  script_cve_id(
    "CVE-2016-6082",
    "CVE-2016-6084",
    "CVE-2016-6085"
  );
  script_bugtraq_id(
    95286,
    95291,
    95297
  );
  script_osvdb_id(
    149108,
    149109,
    149224
  );
  script_xref(name:"IAVB", value:"2017-B-0010");

  script_name(english:"IBM BigFix Platform 9.x < 9.1.9.1301 / 9.2.9.36 / 9.5.4.38 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the IBM BigFix Server.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.0.x or 9.1.x prior to
9.1.9.1301, 9.2.x prior to 9.2.9.36, or 9.5.x prior to 9.5.4.38. It
is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to a
    use-after-free race condition. An unauthenticated, remote
    attacker can exploit this to execute arbitrary code.
    (CVE-2016-6082)

  - A denial of service vulnerability exists that is
    triggered when handling specially crafted XMLSchema
    requests. An unauthenticated, adjacent attacker can
    exploit this to crash the BES Server. Note that this
    issue only affects 9.0.x or 9.1.x versions prior to
    9.1.9. (CVE-2016-6084)

  - A denial of service vulnerability exists in the BES Root
    Server and BES Relay Memory due to improper handling of
    user-supplied input. An unauthenticated, adjacent
    attacker can exploit this to cause the system to crash.
    (CVE-2016-6085)

Note that, additionally, several vulnerabilities possibly also exist
in the bundled version of OpenSSL included in versions 9.0.x.

IBM BigFix Platform was formerly known as Tivoli Endpoint Manager,
IBM Endpoint Manager, and IBM BigFix Endpoint Manager.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21996339");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21996348");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21996375");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM BigFix Platform version 9.1.9.1301 / 9.2.9.36 /
9.5.4.38 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_endpoint_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_tem_detect.nasl");
  script_require_keys("www/BigFixHTTPServer");
  script_require_ports("Services/www", 52311);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "IBM BigFix Server";
port = get_http_port(default:52311, embedded:FALSE);

version = get_kb_item_or_exit("www/BigFixHTTPServer/"+port+"/version");

if (version == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_SERVER_VER, app_name, port);

if (version !~ "^(\d+\.){2,}\d+$")
  audit(AUDIT_VER_NOT_GRANULAR, app_name, port, version);

fix = NULL;
min_fix = make_array(
  "9.0", "9.1.1301.0",
  "9.1", "9.1.1301.0",
  "9.2", "9.2.9.36",
  "9.5", "9.5.4.38"
);

foreach minver (keys(min_fix))
{
  if (ver_compare(ver:version, minver:minver, fix:min_fix[minver], strict:FALSE) < 0)
  {
    fix = min_fix[minver];
    break;
  }     
}

if (isnull(fix))
  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

report = "";

source = get_kb_item("www/BigFixHTTPServer/"+port+"/source");
if (!isnull(source))
  report += '\n  Source            : ' + source;

report +=
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
