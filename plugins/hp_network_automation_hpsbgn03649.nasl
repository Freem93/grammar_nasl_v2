#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93844);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/12 14:59:31 $");

  script_cve_id("CVE-2016-4385");
  script_bugtraq_id(93109);
  script_osvdb_id(129952, 130424, 144683);
  script_xref(name:"HP", value:"emr_na-c05279098");
  script_xref(name:"HP", value:"HPSBGN03649");
  script_xref(name:"HP", value:"PSRT110129");
  script_xref(name:"ZDI", value: "ZDI-16-523");
  script_xref(name:"CERT", value: "576313");
  script_xref(name:"TRA", value:"TRA-2016-27");

  script_name(english:"HP Network Automation RMI Registry Java Object Deserialization RCE");
  script_summary(english:"Checks the version of HP Network Automation.");

  script_set_attribute(attribute:"synopsis",value:
"An application running on the remote host is affected by a remote code
execution vulnerability.");
  script_set_attribute(attribute:"description",value:
"The HP Network Automation application running on the remote host is
version 9.1x, 9.2x, 10.00.x prior to 10.00.02.01, 10.10.x, or
10.11.x prior to 10.11.00.01. It is, therefore, affected by a remote
code execution vulnerability in the RMI registry due to unsafe
deserialize calls of unauthenticated Java objects to the Apache
Commons Collections (ACC) library. An unauthenticated, remote attacker
can exploit this, by sending a specially crafted request, to execute
arbitrary code on the target host.");
  # http://h20565.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-c05279098
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?3ab8d0ab");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"see_also",value:"http://www.tenable.com/security/research/tra-2016-27");
  script_set_attribute(attribute:"solution",value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/04");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:hp:network_automation");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_network_automation_detect.nbin");
  script_require_keys("installed_sw/HP Network Automation");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "HP Network Automation";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

port    = get_http_port(default:443);
install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);
version = install['version'];
url     = build_url(port:port,qs:install['path']);

fix = NULL;

if (version =~ "^9\.1[0-9](\.|$)")
{
  fix = "10.20";
}
else if (version =~ "^9\.2[0-9](\.|$)")
{
  fix = "10.20";
}
else if (version =~ "^10\.00(\.|$)")
{
  fix = "10.00.02.01";
}
else if (version =~ "^10.1[0-1](\.|$)")
{
  fix="10.11.00.01";
}

if (isnull(fix))
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0 )
{
  items = make_array("URL", url,
                     "Installed version", version,
                     "Fixed version", fix
                    );
  order = make_list("URL", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, url, version);
