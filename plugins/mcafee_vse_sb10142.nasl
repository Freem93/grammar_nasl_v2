#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87500);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/05/12 17:36:03 $");

  script_cve_id("CVE-2015-8577");
  script_bugtraq_id(78810);
  script_osvdb_id(131494);
  script_xref(name:"MCAFEE-SB", value:"SB10142");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 6 Buffer Overflow Protection (BOP) Security Bypass (SB10142)");
  script_summary(english:"Checks the file version of mfeapconfig.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an antivirus application installed that is
affected by a buffer overflow protection (BOP) security bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise installed on the remote
Windows host is prior to 8.8 Patch 6. It is, therefore, affected by
a buffer overflow protection (BOP) security bypass vulnerability due
to insecure allocation of memory pages with Read, Write, and Execute
(RWX) permissions at a constant predictable address. A local attacker
can exploit this to gain access to the address space layout.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10142");
  script_set_attribute(attribute:"see_also", value:"http://blog.ensilo.com/the-av-vulnerability-that-bypasses-mitigations");
  # http://breakingmalware.com/vulnerabilities/sedating-watchdog-abusing-security-products-bypass-mitigations/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4927ba47");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 6.
Alternatively, apply the workarounds referenced in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
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
product_name = get_kb_item_or_exit("Antivirus/McAfee/product_name");
version      = get_kb_item_or_exit("Antivirus/McAfee/product_version");
arch         = get_kb_item_or_exit("SMB/ARCH");

if ("McAfee VirusScan Enterprise" >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

# Check OS arch only 32 bit affected
if (arch != "x86")
  audit(AUDIT_HOST_NOT, "a 32-bit operating system");

# Check for work around
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key  = "SOFTWARE\McAfee\SystemCore\VSCore\On Access Scanner\BehaviourBlocking\BOPEnabled";
bop_enabled = get_registry_value(handle:hklm, item:key);
key  = "SOFTWARE\McAfee\SystemCore\szInstallDir32";
path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (isnull(path))
  audit(AUDIT_FN_FAIL, 'get_registry_value', "NULL when accessing registry value 'szInstallDir32'");

if (isnull(bop_enabled))
  audit(AUDIT_FN_FAIL, 'get_registry_value', "NULL when accessing registry value 'BOPenabled'");

bop_enabled = int(bop_enabled);
if (bop_enabled == 0)
  audit(AUDIT_HOST_NOT, "affected because McAfee AntiVirus Buffer Overflow Protection is not enabled.");

# Check for patch
dll = path + "\mfebopa.dll";
dll_ver = hotfix_get_fversion(path:dll);
hotfix_check_fversion_end();
hotfix_handle_error(error_code:dll_ver['error'], file:dll, appname:"McAfee VirusScan Enterprise", exit_on_fail:TRUE);

dll_ver = join(dll_ver['value'], sep:'.');
dll_fix = '15.4.0.674';

if (ver_compare(ver:dll_ver, fix:dll_fix, strict:FALSE) == -1)
  vuln = TRUE;

if (vuln)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Product version      : ' + version +
      '\n  File                 : ' + dll +
      '\n  Current file version : ' + dll_ver +
      '\n  Fixed file version   : ' + dll_fix +
      '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, version);
