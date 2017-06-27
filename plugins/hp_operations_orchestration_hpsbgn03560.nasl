#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90099);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2017/01/16 16:05:33 $");

  script_cve_id("CVE-2016-1997");
  script_bugtraq_id(85006);
  script_osvdb_id(129952, 130424, 136044);
  script_xref(name:"HP", value:"HPSBGN03560");
  script_xref(name:"HP", value:"emr_na-c05050545");
  script_xref(name:"HP", value:"PSRT110056");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"HP Operations Orchestration 10.x < 10.51 Java Object Deserialization RCE");
  script_summary(english:"Checks the HP Operations Orchestration version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Operations Orchestration installed on the remote
host is 10.x prior to 10.51. It is, therefore, affected by a remote
code execution vulnerability due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted serialized Java object, to execute arbitrary code on
the target host.");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?calledBy=&docId=emr_na-c05050545
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f5b84cf");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP Operations Orchestration version 10.51 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:operations_orchestration");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("hp_operations_orchestration_detect.nbin");
  script_require_ports("Services/www", 8080, 8443);
  script_require_keys("installed_sw/HP Operations Orchestration");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "HP Operations Orchestration";

get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:8080);

install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

dir = install['path'];
version = install['version'];

install_url = build_url(port:port, qs:dir);
fix = "10.51";

if (version =~ '^10\\.' && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  items = make_array("URL", install_url, "Installed version", version, "Fixed version", fix);
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
