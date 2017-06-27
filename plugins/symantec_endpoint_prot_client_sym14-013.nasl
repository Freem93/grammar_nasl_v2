#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77050);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/19 18:02:20 $");

  script_cve_id("CVE-2014-3434");
  script_bugtraq_id(68946);
  script_osvdb_id(109663);
  script_xref(name:"CERT", value:"252068");
  script_xref(name:"EDB-ID", value:"34272");

  script_name(english:"Symantec Endpoint Protection Client < 12.1 RU4 MP1b (SYM14-013)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is affected by a local privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Client running on the
remote host is either 11.x or 12.x prior to 12.1 RU4 MP1b. It is,
therefore, affected by a local privilege escalation vulnerability.

A flaw exists in the sysplant driver due to insufficient validation of
external input. An attacker, using specially crafted IOCTL code, could
cause a kernel pool overflow resulting in elevated privileges to
SYSTEM.");
  # http://www.symantec.com/business/support/index?page=content&id=TECH223338
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1de9bbfe");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20140804_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78cc154a");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 12.1 RU4 MP1b (12.1.4112.4156) or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';
vuln = FALSE;

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

major_ver = split(display_ver, sep:'.', keep:FALSE);
major_ver = int(major_ver[0]);

fixed_ver = '12.1.4112.4156';

if (report_paranoia < 2)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  key = "SYSTEM\CurrentControlSet\services\SysPlant\Start";
  res = get_registry_value(handle:hklm, item:key);
  RegCloseKey(handle:hklm);
  close_registry();

  if (empty_or_null(res)) audit(AUDIT_NOT_INST, 'The Application and Device Control driver');
  if (res == 4) exit(0, 'The host is not affected because the Application and Device Control driver is disabled.');
}

# Version 11.x up to the fixed version are affected
if (major_ver >= 11 && ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1) vuln = TRUE;

# Small Business Edition version 12.1 is not affected
if (edition == 'sepsb' && ver_compare(ver:display_ver, fix:'12.1', strict:FALSE) >= 0) vuln = FALSE;

if (vuln)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Product           : ' + app +
      '\n  Installed version : ' + display_ver +
      '\n  Fixed version     : ' + fixed_ver +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
