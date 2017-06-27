#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59209);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2012-0296",
    "CVE-2012-0297",
    "CVE-2012-0298",
    "CVE-2012-0299"
 );
  script_bugtraq_id(53396, 53442, 53443, 53444);
  script_osvdb_id(
    81710,
    82022,
    82023,
    82024,
    82025,
    82925,
    82926,
    82927,
    83402
  );
  script_xref(name:"TRA", value:"TRA-2012-03");
  script_xref(name:"EDB-ID", value:"18832");
  script_xref(name:"EDB-ID", value:"18932");
  script_xref(name:"EDB-ID", value:"18942");
  script_xref(name:"EDB-ID", value:"19065");
  script_xref(name:"EDB-ID", value:"19406");

  script_name(english:"Symantec Web Gateway < 5.0.3 Multiple Vulnerabilities (SYM12-006) (version check)");
  script_summary(english:"Checks SWG version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application hosted on the remote web server has
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote web server
is hosting Symantec Web Gateway before version 5.0.3, which has the
following vulnerabilities :

  -There are multiple cross-site scripting vulnerabilities.
   (CVE-2012-0296)

  - Multiple shell command injection and local file inclusion
    vulnerabilities exist that could lead to arbitrary code
    execution. (CVE-2012-0297)

  - Unauthenticated users are allowed to read/delete arbitrary
    files as root. (CVE-2012-0298)

  - A file upload vulnerability exists that could lead to
    arbitrary code execution. (CVE-2012-0299)

A remote, unauthenticated attacker could exploit the code execution
vulnerabilities to execute commands as the apache user.  After
exploitation, obtaining a root shell is trivial."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-03");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-090/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-091/");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523064/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/523065/30/0/threaded");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120517_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?337b743c");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway version 5.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Symantec Web Gateway 5.0.2 File Upload");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Symantec Web Gateway 5.0.2.8 Arbitrary PHP File Upload Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
;# XSS disclosed on exploit-db.com

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/04");  
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);
dir = install['dir'];
ver = install['ver'];
fix = '5.0.3';

url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Web Gateway', url);

if (ver =~ '^5' && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/' + port + '/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + ver +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Symantec Web Gateway', url, ver);

