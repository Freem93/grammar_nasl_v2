#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83292);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/01/30 19:28:01 $");

  script_cve_id("CVE-2013-2251", "CVE-2013-4316");
  script_bugtraq_id(61189, 62587);
  script_osvdb_id(95405, 97542);
  script_xref(name:"EDB-ID", value:"27135");

  script_name(english:"MySQL Enterprise Monitor < 2.3.14 Apache Struts Multiple Vulnerabilities");
  script_summary(english:"Checks the version of MySQL Enterprise Monitor.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the MySQL Enterprise Monitor
running on the remote host is affected by the multiple vulnerabilities
in the bundled version of Apache Struts :

  - Input validation errors exist that allows the execution
    of arbitrary Object-Graph Navigation Language (OGNL)
    expressions via specially crafted parameters to the
    DefaultActionMapper. (CVE-2013-2251)

  - Multiple unspecified vulnerabilities exist related to
    dynamic method invocation being enabled by default.
    (CVE-2013-4316)");
  # http://www.oracle.com/technetwork/topics/security/cpujan2014-1972949.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17c46362");
  # http://www.oracle.com/technetwork/topics/security/cpuoct2013-1899837.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ac29c174");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-016.html");
  script_set_attribute(attribute:"see_also", value:"https://struts.apache.org/docs/s2-019.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL Enterprise Monitor 2.3.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:enterprise_monitor");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");

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

fix  = "2.3.14";
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
