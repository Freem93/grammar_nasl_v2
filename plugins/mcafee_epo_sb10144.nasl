#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
  {
script_id(88624);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/02/13 17:29:26 $");

  script_cve_id("CVE-2015-8765");
  script_bugtraq_id(85696);
  script_osvdb_id(129952, 130424, 132458);
  script_xref(name:"CERT", value:"576313");
  script_xref(name:"MCAFEE-SB", value:"SB10144");

  script_name(english:"McAfee ePolicy Orchestrator Java Object Deserialization RCE");
  script_summary(english:"Checks registry/fs for the common-collections version.");

  script_set_attribute(attribute:"synopsis", value:
"A security management application installed on the remote Windows host
is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The McAfee ePolicy Orchestrator (ePO) installed on the remote Windows
host is affected by a remote code execution vulnerability due to
unsafe deserialize calls of unauthenticated Java objects to the Apache
Commons Collections (ACC) library. An unauthenticated, remote attacker
can exploit this to execute arbitrary code on the target host.");
  # https://kc.mcafee.com/corporate/index?page=content&id=SB10144#remediation
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?857cd252");
  # https://kc.mcafee.com/resources/sites/MCAFEE/content/live/PRODUCT_DOCUMENTATION/26000/PD26308/en_US/ReleaseNotes_epo5xHF1106041.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f7a4795");
  # http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/ 
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0204f30");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee ePO version 5.1.3 / 5.3.1 and then apply hotfix
EPO5xHF1106041.zip. A patch for ePO version 5.1.4  is scheduled to be
released in Q2 of 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:epolicy_orchestrator");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("mcafee_epo_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated","installed_sw/McAfee ePO");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee ePO";
install = get_single_install(
  app_name : app_name,
  exit_if_unknown_ver : FALSE
);
dir = install['path'];
ver = install['version'];
report = NULL;

# Check version of common-collections jar
jar_path = hotfix_append_path(path:dir, value:"Installer\\Core\\lib");
share = hotfix_path2share(path:jar_path);
basedir = ereg_replace(string:jar_path, pattern:"^\w:(.*)", replace:"\1");
jars = list_dir(basedir:basedir, level:1, file_pat:"commons-collections.*\.jar$", share:share);
if (isnull(jars)) 
{
  exit(1, "No commons-collections jar file found.");
}
match = eregmatch(string:jars[0], pattern:"commons\-collections\-([0-9\.]+)\.jar$");

hotfix_check_fversion_end();
if (isnull(match))
{
  exit(1,"A commons-collections jar file exists, however it does not have a version.");
}

if(ver_compare(ver:match[1], fix:"3.2.2", strict:FALSE) < 0)
  {
    report =
      '\n Application: McAfee ePolicy Orchestrator ' + ver +
      '\n Path       : ' + jar_path +
      '\n Version    : ' + match[1]+
      '\n Fix        : Upgrade to 5.1.3 or 5.3.1 and then apply
                       hotfix EPO5xHF1106041.zip.
                       For ePO 5.1.4, contact Vendor.';
  } else {
    audit(AUDIT_INST_VER_NOT_VULN, app_name + ver + "commons-collections jar", match[1]);
}

if (isnull(report))
  audit(AUDIT_UNINST, 'McAfee ePO');

port = kb_smb_transport();

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole(port);
