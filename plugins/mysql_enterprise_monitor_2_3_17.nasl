#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83293);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id(
    "CVE-2014-0050",
    "CVE-2014-0094",
    "CVE-2014-0112",
    "CVE-2014-0113",
    "CVE-2014-0116"
  );
  script_bugtraq_id(65400, 65999, 67064, 67081, 67218);
  script_osvdb_id(102945, 103918, 106550);
  script_xref(name:"CERT", value:"719225");
  script_xref(name:"EDB-ID", value:"33142");
  script_xref(name:"EDB-ID", value:"31615");

  script_name(english:"MySQL Enterprise Monitor < 2.3.17 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
running on the remote host is affected by multiple vulnerabilities : 

  - A flaw exists within 'MultipartStream.java' in Apache
    Commons FileUpload when parsing malformed Content-Type
    headers. A remote attacker, using a crafted header,
    can exploit this to cause an infinite loop, resulting
    in a denial of service. (CVE-2014-0050)

  - Security bypass flaws exist in the ParametersInterceptor
    and CookieInterceptor classes, within the included
    Apache Struts 2 component, which are due to a failure to
    properly restrict access to their getClass() methods. A
    remote attacker, using a crafted request, can exploit
    these flaws to manipulate the ClassLoader, thus allowing
    the execution of arbitrary code or modification of the
    session state. Note that vulnerabilities CVE-2014-0112
    and CVE-2014-0116 occurred because the patches for
    CVE-2014-0094 and CVE-2014-0113, respectively, were not
    complete fixes. (CVE-2014-0094, CVE-2014-0112,
    CVE-2014-0113, CVE-2014-0116)");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-021");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-022");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Enterprise Monitor 2.3.17 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Struts ClassLoader Manipulation Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:enterprise_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");
  script_require_ports("Services/www", 18080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app  = "MySQL Enterprise Monitor";
get_install_count(app_name:app, exit_if_zero:TRUE);

fix  = "2.3.17";
port = get_http_port(default:18080);

install = get_single_install(app_name:app, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
install_url = build_url(port:port, qs:"/");

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
