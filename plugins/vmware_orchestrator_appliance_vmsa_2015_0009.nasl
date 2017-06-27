#TRUSTED ad1811f79e411bcdd746556835c2ff41004db21b422c4a5c766934ea2e06746a0f5f3d794d3dca2eff8598cb2f44ce621fd59b4d2d841576b52637ac67885f5b5d1650ff57971e1304361153b53deb6b5c10e038b95c4d4c903226b1f47ecc67f0a161044bfe18e089281f2e630ea3d024c4aa5ac030470ed287de392f14b078d07b8fe6e4adc24f54688e560b19bd0e3ddff4e1e2cdd560ba854cb99821820c0a74c42013fdb2794a4ceffccfc31d61eaabd32c6aca507d103befe39212ab56adc72d8fc5c230fed844ca98b61f8919e8e46d6eea0133bc37c1445c11b461028dea154924d6d3c63c489ddf2bab7de6784aa81927b5e1416ba175699d71f29af354f843f6aa99b0f79a53ab367322e6d1a649aac574f61399d621c351f147463fda30626d8cecb68c159d2e5e52f60b5c8920c93b72e589ed2595f565f53f143b22917d5f3889ed64662b0c409017d247ad5d1bb9a9ae5758320e64e8d67b9e2ce88aca0e8f1710f22ac431914b0bc4db3ec5bc74bead13ea5c9ab62a28f90a51189e01afa129ff2080df3c74e9b5e355c03444847070185d7257ab85c0754898b3a85925b61335859114b3d8746fb904dec3d462a33cd421c242f5c291679ede9ea90318802d208b36ab8cc66f3af2361835e3dac740295618eb29dcc0513c8cc72d4ccd9fcecff1abe0b1dd5475664d83a929f3f61737094bad7435c8fa49
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87762);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/16");

  script_cve_id("CVE-2015-6934");
  script_bugtraq_id(79648);
  script_osvdb_id(129952, 130424, 132090);
  script_xref(name:"VMSA", value:"2015-0009");
  script_xref(name:"IAVB", value:"2016-B-0006");
  script_xref(name:"CERT", value:"576313");

  script_name(english:"VMware vCenter / vRealize Orchestrator Appliance 4.2.x / 5.x / 6.x Java Object Deserialization RCE (VMSA-2015-0009)");
  script_summary(english:"Checks the version of VMware vCenter/vRealize Orchestrator Appliance.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization appliance installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter / vRealize Orchestrator Appliance
installed on the remote host is 4.2.x or 5.x or 6.x and includes the
Apache Commons Collections (ACC) library version 3.2.1. It is,
therefore, affected by a remote code execution vulnerability due to
unsafe deserialize calls of unauthenticated Java objects to the ACC
library. An unauthenticated, remote attacker can exploit this, by
sending a crafted request, to execute arbitrary code on the target
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0009");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2141244");
  # https://blogs.apache.org/foundation/entry/apache_commons_statement_to_widespread
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?91868e8b");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"see_also", value:"http://www.infoq.com/news/2015/11/commons-exploit");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in VMware KB 2141244.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

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

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/VMware vCenter Orchestrator/Version", "Host/VMware vCenter Orchestrator/VerUI", "Host/VMware vCenter Orchestrator/Build", "HostLevelChecks/proto", "Host/local_checks_enabled");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

version = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/Version");
verui = get_kb_item_or_exit("Host/VMware vCenter Orchestrator/VerUI");

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

app_name = "VMware vCenter/vRealize Orchestrator Appliance";

if (version !~ "^4\.2($|\.)" && version !~ "^5\." && version !~ "^6\.")
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

# if any of these files exist, we are vulnerable
# /var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar
# /var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar
# /opt/vmo/app-server/server/vmo/lib/commons-collections.jar
# /opt/vmo/configuration/jetty/lib/ext/commons-collections.jar

file1 = "/var/lib/vco/app-server/deploy/vco/WEB-INF/lib/commons-collections-3.2.1.jar";
file2 = "/var/lib/vco/configuration/lib/o11n/commons-collections-3.2.1.jar";
file3 = "/opt/vmo/app-server/server/vmo/lib/commons-collections.jar";
file4 = "/opt/vmo/configuration/jetty/lib/ext/commons-collections.jar";

file1_exists = info_send_cmd(cmd:"ls " + file1 + " 2>/dev/null");
file2_exists = info_send_cmd(cmd:"ls " + file2 + " 2>/dev/null");
file3_exists = info_send_cmd(cmd:"ls " + file3 + " 2>/dev/null");
file4_exists = info_send_cmd(cmd:"ls " + file4 + " 2>/dev/null");

if (empty_or_null(file1_exists) && empty_or_null(file2_exists) && empty_or_null(file3_exists) && empty_or_null(file4_exists))
  audit(AUDIT_INST_VER_NOT_VULN, app_name, verui);

report = '\n  Installed version  : ' + verui;
if (!empty_or_null(file1_exists))
  report += '\n  Vulnerable library : ' + file1;
if (!empty_or_null(file2_exists))
  report += '\n  Vulnerable library : ' + file2;
if (!empty_or_null(file3_exists))
  report += '\n  Vulnerable library : ' + file3;
if (!empty_or_null(file4_exists))
  report += '\n  Vulnerable library : ' + file4;
report +=  '\n';

security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
