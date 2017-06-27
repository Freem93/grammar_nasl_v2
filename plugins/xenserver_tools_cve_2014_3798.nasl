#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74328);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/06 00:03:10 $");

  script_cve_id("CVE-2014-3798");
  script_bugtraq_id(67693);
  script_osvdb_id(107493);

  script_name(english:"Citrix XenServer Windows Guest Tools Remote DoS");
  script_summary(english:"Checks xenvif.sys version");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a vulnerable version of XenServer Tools
that may allow a remote, unauthenticated attacker to crash the host by
sending specially crafted packets.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX140814");
  script_set_attribute(attribute:"solution", value:"Apply the appropriate patch per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenserver_tools");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("xenserver_tools_installed.nbin");
  script_require_keys("SMB/xenserver_tools/Version",
                      "SMB/xenserver_tools/Path");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("SMB/xenserver_tools/Version");
path    = get_kb_item_or_exit("SMB/xenserver_tools/Path");

if (version !~ "^6\.[21](\.|$)" && version !~ "^6\.0\.[20](\.|$)") audit(AUDIT_INST_VER_NOT_VULN, "Citrix XenServer Tools", version);

driver = hotfix_append_path(path:path, value:'xenvif.sys');
ver = hotfix_get_pversion(path:driver);

if (ver['error'] != HCF_OK)
{
  hotfix_handle_error(error_code: ver['error'],
                      file: 'xenvif.sys',
                      appname: 'Citrix XenServer Tools',
                      exit_on_fail: TRUE);
}

hotfix_check_fversion_end();

p_version = join(ver['value'], sep:'.');

fix_version = '6.2.50.76504';

if (ver_compare(fix:fix_version, ver:p_version, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report = '\n  XenServer Tools version      : ' + version +
             '\n  xenvif.sys installed version : ' + p_version +
             '\n  xenvif.sys fixed version     : ' + fix_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Citrix XenServer Tools 'xenvif.sys'", version, path);
