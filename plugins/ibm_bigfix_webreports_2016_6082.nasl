#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96626);
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

  script_name(english:"IBM BigFix Platform 9.x < 9.1.9 / 9.2.x < 9.2.9 / 9.5.x < 9.5.4 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of the IBM BigFix Web Reports.");

  script_set_attribute(attribute:"synopsis", value:
"An infrastructure management application running on the remote host
is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the IBM BigFix Platform
application running on the remote host is 9.x prior to 9.1.9, 9.2.x
prior to 9.2.9, or 9.5.x prior to 9.5.4. It is, therefore, affected by
multiple vulnerabilities :

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
    Server and BES Relay Memory when handling unspecified
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
"Upgrade to IBM BigFix Platform version 9.1.9 / 9.2.9 / 9.5.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:bigfix_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_bigfix_webreports_detect.nbin");
  script_require_keys("installed_sw/IBM BigFix Web Reports");
  script_require_ports("Services/www", 80, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "IBM BigFix Web Reports";
port = get_http_port(default:8080);
install = get_install_from_kb(appname: appname, port: port, exit_on_fail: TRUE);

dir = install["dir"];
url = build_url(port:port, qs:dir);

version = install["ver"];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, url);

ver = split(version, sep:".", keep:FALSE);
for (i=0; i<max_index(ver); i++)
{
  ver[i] = int(ver[i]);
}

if(max_index(ver) < 3) audit(AUDIT_VER_NOT_GRANULAR, appname, port, version);

# All 9.0 is vuln.
# 9.1 before 9.1.9 is vuln
# 9.2 before 9.2.9 is vuln
# 9.5 before 9.5.4 is vuln
# assume version < 9.x not vulnerable as they are not listed in the advisory
report = NULL;
if (ver[0] == 9)
{
  if ((ver[1] == 0) || (ver[1] == 1 && ver[2] < 9))
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.1.9.x\n';
  }
  else if (ver[1] == 2 && ver[2] < 9)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.2.9.x\n';
  }
  else if (ver[1] == 5 && ver[2] < 4)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 9.5.4.x\n';
  }  
}

if (!isnull(report))
{
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else 
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
}
