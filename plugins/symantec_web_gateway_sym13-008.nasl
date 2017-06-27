#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(69179);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id(
    "CVE-2013-1616",
    "CVE-2013-1617",
    "CVE-2013-4670",
    "CVE-2013-4671",
    "CVE-2013-4672",
    "CVE-2013-4673"
  );
  script_bugtraq_id(61101, 61102, 61103, 61104, 61105, 61106);
  script_osvdb_id(
    95690,
    95692,
    95695,
    95696,
    95698,
    95699,
    95700,
    95702,
    95703
  );
  script_xref(name:"EDB-ID", value:"27136");

  script_name(english:"Symantec Web Gateway < 5.1.1 Multiple Vulnerabilities (SYM13-008)");
  script_summary(english:"Checks SWG version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web security application hosted on the remote web server has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported version number, the remote web server is
hosting Symantec Web Gateway before version 5.1.1, which has the
following vulnerabilities :

  - Multiple cross-site scripting vulnerabilities exist.
    (CVE-2013-4670)

  - It is possible to inject arbitrary operating system
    commands via the 'nameConfig.php' and
    'networkConfig.php' scripts. (CVE-2013-1616)

  - A misconfiguration in the '/etc/sudoers' file allows
    the user's 'apache' and 'admin' to run several
    commands with root privileges. (CVE-2013-4672)

  - Multiple SQL injection vulnerabilities exist.
    (CVE-2013-1617)

  - A cross-site request forgery vulnerability exists in the
    'ldapConfig.php' script. (CVE-2013-4671)");

  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20130725_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fd5baa6");
  # https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130726-0_Symantec_Web_Gateway_Multiple_Vulnerabilities_v10.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2a4b289");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2013/Jul/177");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec Web Gateway version 5.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:web_gateway");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_web_gateway_detect.nasl");
  script_require_keys("www/symantec_web_gateway");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:443, php:TRUE);
install = get_install_from_kb(appname:'symantec_web_gateway', port:port, exit_on_fail:TRUE);
dir = install['dir'];
ver = install['ver'];
fix = '5.1.1';

url = build_url(port:port, qs:dir);

if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_WEB_APP_VER, 'Symantec Web Gateway', url);

if (ver =~ '^5\\.' && ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/SQLInjection', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

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

