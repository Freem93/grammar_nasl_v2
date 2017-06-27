#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94933);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/11/21 15:08:28 $");

  script_cve_id(
    "CVE-2016-4398",
    "CVE-2016-4399",
    "CVE-2016-4400"
  );
  script_bugtraq_id(94195);
  script_osvdb_id(
    129952,
    130424,
    146989,
    146990,
    146991
  );
  script_xref(name:"HP", value:"emr_na-c05325823");
  script_xref(name:"IAVA", value:"2016-A-0325");
  script_xref(name:"HP", value:"HPSBGN03656");
  script_xref(name:"HP", value:"PSRT110235");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"HP Network Node Manager i < 10.20 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of HP Network Node Manager i.");

  script_set_attribute(attribute:"synopsis", value:
"A web management application running on the remote host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The HP Network Node Manager i (NNMi) server running on the remote host
is a version prior to 10.20. It is, therefore, affected by multiple
vulnerabilities :

  - A remote code execution vulnerability exists due to
    unsafe deserialize calls of unauthenticated Java objects
    to the Apache Commons Collections (ACC) library. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code on the target host.
    (CVE-2016-4398)

  - Multiple reflected cross-site scripting (XSS)
    vulnerabilities exist due to improper validation of
    input before returning it to users. An unauthenticated,
    remote attacker can exploit these, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2016-4399, CVE-2016-4400)");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  # http://h20566.www2.hpe.com/hpsc/doc/public/display?docLocale=en_US&docId=emr_na-c05325823
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9723ef5a");
  script_set_attribute(attribute:"solution", value:
"Upgrade NNMi to version 10.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:network_node_manager_i");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_nnmi_console_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("installed_sw/HP Network Node Manager i", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

appname = "HP Network Node Manager i";

get_install_count(app_name:appname, exit_if_zero:TRUE);
port = get_http_port(default:80);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);

# We don't know the patch version so make this paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixed = "10.20";
if (ver_compare(ver:install["version"], fix:fixed) == -1)
{
  report =
    '\n  Path              : ' + build_url(port:port, qs:install['path']) +
    '\n  Installed version : ' + install["version"] +
    '\n  Fixed version     : ' + fixed + '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report, xss:TRUE);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname, install["version"]);
