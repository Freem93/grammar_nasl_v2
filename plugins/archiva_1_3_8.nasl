#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73761);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/11 19:58:29 $");

  script_cve_id("CVE-2013-2187", "CVE-2013-2251");
  script_bugtraq_id(61189, 66991, 66998);
  script_osvdb_id(95405, 106094);
  script_xref(name:"EDB-ID", value:"27135");

  script_name(english:"Apache Archiva 1.2.x <= 1.2.2 / 1.3.x <= 1.3.6 Multiple Vulnerabilities");
  script_summary(english:"Checks Archiva version");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the instance of Apache Archiva
hosted on the remote web server is 1.2.x prior than or equal to 1.2.2
or 1.3.x prior than or equal to 1.3.6 and thus is affected by the
following vulnerabilities :

  - An input validation error exists related to
    unspecified scripts and unspecified parameters that
    could allow cross-site scripting attacks.
    (CVE-2013-2187)

  - Input validation errors exist related to the bundled
    version of Apache Struts that could allow arbitrary
    Object-Graph Navigation Language (OGNL) expression
    execution via specially crafted requests.
    (CVE-2013-2251)");
  script_set_attribute(attribute:"see_also", value:"http://archiva.apache.org/security.html");
  script_set_attribute(attribute:"see_also", value:"http://commons.apache.org/proper/commons-ognl/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache Archiva 1.3.8 / 2.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Apache-Struts DefaultActionMapper < 2.3.15.1 RCE Linux");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts 2 DefaultActionMapper Prefixes OGNL Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:archiva");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("archiva_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/archiva");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8080, embedded:FALSE);

install = get_install_from_kb(appname:'archiva', port:port, exit_on_fail:TRUE);
dir = install['dir'];
install_url = build_url(port:port, qs:dir+'/index.action');
version = install['ver'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Apache Archiva", install_url);

if (version !~ "^1\.[23]($|\.)") audit(AUDIT_WEB_APP_NOT_INST, "Apache Archiva 1.2.x / 1.3.x", port);

# Affected (per NVD) :
# 1.2.x <= 1.2.2
# 1.3.x <= 1.3.6
# Fixed (per vendor) :
# 1.3.8
# 2.0.1
if (
  version =~ "^1\.2($|[^0-9.])" ||
  version =~ "^1\.2\.[012]($|[^0-9])" ||
  version =~ "^1\.3($|[^0-9.])" ||
  version =~ "^1\.3\.[0-6]($|[^0-9])"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.3.8 / 2.0.1' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Apache Archiva", install_url, version);
