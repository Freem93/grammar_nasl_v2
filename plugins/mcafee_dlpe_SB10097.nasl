#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81247);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2015-1305");
  script_bugtraq_id(72395);
  script_osvdb_id(117345);
  script_xref(name:"MCAFEE-SB", value:"SB10097");

  script_name(english:"McAfee DLPe Agent Privilege Escalation Vulnerability on Windows XP (SB10097)");
  script_summary(english:"Checks the version of McAfee DLPe.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows XP host is running a version of the McAfee DLPe
agent that is affected by a privilege escalation vulnerability, which
a local attacker can exploit by sending specially crafted commands to
a kernel mode driver.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10097");
  script_set_attribute(attribute:"solution", value:"Upgrade to McAfee DLPe 9.3 Patch 4 or higher.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:data_loss_prevention_endpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mcafee_dlpe_agent_installed.nbin");
  script_require_keys("installed_sw/McAfee DLPe Agent");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app_name = "McAfee DLPe Agent";
get_install_count(app_name:app_name, exit_if_zero:TRUE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >!< productname) audit(AUDIT_OS_NOT, "Windows XP");

port = get_kb_item("SMB/transport");
if(!port)port = 445;

install = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version = install['version'];
path = install['path'];

if(ver_compare(ver:version, fix:'9.3.400', strict:FALSE) == -1)
{
  if(report_verbosity > 0)
  {
    report = '\n  Install Path  : ' + path +
             '\n  Version       : ' + version +
             '\n  Fixed Version : 9.3.400\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
