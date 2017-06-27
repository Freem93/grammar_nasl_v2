#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87763);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/08/16 14:42:21 $");

  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_osvdb_id(132090);
  script_xref(name:"VMSA", value:"2015-0009");
  script_xref(name:"IAVB", value:"2016-B-0006");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"VMware vCenter / vRealize Orchestrator 4.2.x / 5.x / 6.x Java Object Deserialization RCE (VMSA-2015-0009)");
  script_summary(english:"Checks the version of VMware vCenter/vRealize Orchestrator.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter / vRealize Orchestrator installed on the
remote host is 4.2.x, 5.x, or 6.x and includes the Apache Commons
Collections (ACC) library version 3.2.1. It is, therefore, affected by
a remote code execution vulnerability due to unsafe deserialize calls
of unauthenticated Java objects to the ACC library. An
unauthenticated, remote attacker can exploit this, by sending a
crafted request, to execute arbitrary code on the target host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0009");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2141244");
  # https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91868e8b");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"see_also", value:"http://www.infoq.com/news/2015/11/commons-exploit");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in VMware KB 2141244.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/06");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_orchestrator");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vrealize_orchestrator");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_orchestrator_installed.nbin");
  script_require_keys("installed_sw/VMware vCenter Orchestrator");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

app_name = "VMware vCenter Orchestrator";

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);

version = install['version'];
verui = install['VerUI'];
path  = install['path'];

app_name = "VMware vCenter/vRealize Orchestrator";

if (version !~ "^4\.2($|\.)" && version !~ "^5\." && version !~ "^6\.")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

# if any of these files exist, we are vulnerable
# orchestrator_install_folder\app-server\deploy\vco\WEB-INF\lib\commons-collections-3.2.1.jar
# orchestrator_install_folder\configuration\lib\o11n\commons-collections-3.2.1.jar
# orchestrator_install_folder\app-server\server\vmo\lib\commons-collections.jar
# orchestrator_install_folder\configuration\jetty\lib\ext\commons-collections.jar

file1 = hotfix_append_path(path:path, value:"app-server\deploy\vco\WEB-INF\lib\commons-collections-3.2.1.jar");
file2 = hotfix_append_path(path:path, value:"configuration\lib\o11n\commons-collections-3.2.1.jar");
file3 = hotfix_append_path(path:path, value:"app-server\server\vmo\lib\commons-collections.jar");
file4 = hotfix_append_path(path:path, value:"configuration\jetty\lib\ext\commons-collections.jar");

file1_exists = hotfix_file_exists(path:file1);
file2_exists = hotfix_file_exists(path:file2);
file3_exists = hotfix_file_exists(path:file3);
file4_exists = hotfix_file_exists(path:file4);

hotfix_check_fversion_end();

if (!file1_exists && !file2_exists && !file3_exists && !file4_exists)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, verui, path);

report = '\n  Installed version  : ' + verui;
if (file1_exists)
  report += '\n  Vulnerable library : ' + file1;
if (file2_exists)
  report += '\n  Vulnerable library : ' + file2;
if (file3_exists)
  report += '\n  Vulnerable library : ' + file3;
if (file4_exists)
  report += '\n  Vulnerable library : ' + file4;
report +=  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
