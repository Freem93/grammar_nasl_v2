#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90199);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_cve_id("CVE-2015-8154");
  script_bugtraq_id(84344);
  script_osvdb_id(136014);

  script_name(english:"Symantec Endpoint Protection Client < 12.1 RU6 MP4 SysPlant.sys Driver RCE (SYM16-003)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Client installed on the
remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Client running on the
remote host is 12.1 prior to 12.1 RU6 MP4. It is, therefore, affected
by a remote code execution vulnerability due to insecure permissions
for the SysPlant.sys driver. A remote attacker can exploit this, via a
crafted HTML document, to execute arbitrary code.");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160317_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94f36bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 12.1 RU6 MP4 or
later. Alternatively, apply the workaround as described in the vendor
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

fixed_ver = '12.1.6860.6400';

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

if (display_ver =~ "^12\.1\." && ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
