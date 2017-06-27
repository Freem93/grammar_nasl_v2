#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72216);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/19 20:46:16 $");

  script_cve_id("CVE-2010-3496");
  script_bugtraq_id(44184);
  script_osvdb_id(75185);
  script_xref(name:"MCAFEE-SB", value:"SB10012");

  script_name(english:"McAfee VirusScan Enterprise 8.5 / 8.7 hcp:// Security Bypass (SB10012)");
  script_summary(english:"Checks if MS10-042 is applied or if 'Disable HCP URLs in Internet Explorer' rule in VSE is enabled");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has an antivirus application that is affected by a
security bypass vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has McAfee VirusScan Enterprise version 8.5 or
8.7.  It is, therefore, affected by a security bypass vulnerability due
to a failure to properly interact with the processing of 'hcp://' URLs. 
This can lead to malware execution prior to detection."
  );
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10012");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the patch from Microsoft Bulletin MS10-042 or enable VirusScan
Enterprise access protection rule 'Disable HCP URLs in Internet
Explorer' (requires Buffer Overflow and Access Protection DAT Version
516 or greater)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mcafee_installed.nasl", "smb_nt_ms10-042.nasl");
  script_require_keys("Antivirus/McAfee/installed", "SMB/Missing/MS10-042");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("Antivirus/McAfee/installed");
get_kb_item_or_exit("SMB/Missing/MS10-042");

product = get_kb_item_or_exit("Antivirus/McAfee/product_name");
product_version = get_kb_item_or_exit("Antivirus/McAfee/product_version");

# Make sure VSE is installed and that it is either version 8.5 or 8.7
if ('McAfee VirusScan Enterprise' >!< product) audit(AUDIT_INST_VER_NOT_VULN, product);
if (product_version !~ '^8\\.(7|5)(\\.\\d+)*$') audit(AUDIT_INST_VER_NOT_VULN, product, product_version);

# If MS10-042 is missing, check for the relevant Access Protection rule.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\McAfee\VSCore\On Access Scanner\BehaviourBlocking\AccessProtectionUserRules";
rules = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
close_registry();

hcp_rule = "UserEnforce CO14 1";

if (hcp_rule >!< rules)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n' + '  Product version : ' + product_version +
      '\n' +
      '\n' + 'MS10-042 is not installed and \'Disable HCP URLs in Internet Explorer\''+
      '\n' + 'Access protection rule is disabled.' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, product, product_version);
