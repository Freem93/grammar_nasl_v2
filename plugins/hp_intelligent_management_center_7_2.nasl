#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93097);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2016-4372");
  script_bugtraq_id(91739);
  script_osvdb_id(129952, 130424, 141491);
  script_xref(name:"CERT", value:"576313");
  script_xref(name:"HP", value:"emr_na-c05200601");
  script_xref(name:"HP", value:"HPSBHF03608");
  script_xref(name:"HP", value:"PSRT110005");
  script_xref(name:"HP", value:"PSRT110121");

  script_name(english:"HP Intelligent Management Center Java Object Deserialization RCE");
  script_summary(english:"Checks the version of HP Intelligent Management Center products.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote web server is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of HP Intelligent Management Center (IMC) installed on the
remote Windows host is prior to 7.2. It is, therefore, affected by a
remote code execution vulnerability due to unsafe deserialize calls of
unauthenticated Java objects to the Apache Commons Collections (ACC)
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted HTTP request, to execute arbitrary code on the
target host.");
  # https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05200601
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3565148");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"solution", value:
"Upgrade to HP IMC version 7.2 E0403P04 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:intelligent_management_center");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("hp_intelligent_management_center_installed.nasl");
  script_require_keys("installed_sw/HP Intelligent Management Center Application");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'HP Intelligent Management Center Application';

# Pull the installation information from the KB.
install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

path = install['path'];
version = install['version'];

fix = NULL;
if (version =~ "^[0-6](\.[0-9]+)*$" || # e.g. 5, 6.999
    version =~ "^7\.0([0-9]|\.[0-9]+)*$" || # e.g. 7.01, 7.0.2
    version =~ "^7(\.[0-1])?$" # e.g. 7, 7.1
)
{
  fix = "7.2";
}

if (!isnull(fix) && ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  port = get_kb_item("SMB/transport");
  if (isnull(port))
    port = 445;

  items = make_array("Installed version", version,
                     "Fixed version", fix,
                     "Path", path
                    );

  order = make_list("Path", "Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);

}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
