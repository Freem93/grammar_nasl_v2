#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(70741);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/06/13 13:30:09 $");

  script_cve_id("CVE-2013-6077");
  script_bugtraq_id(63413);
  script_osvdb_id(98890);

  script_name(english:"Citrix XenDesktop BrokerAccessPolicyRule Policy Rule Remote Security Bypass");
  script_summary(english:"Checks version of Citrix XenDesktop");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host may be affected by a remote security bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Citrix XenDesktop that could be
affected by a remote security bypass vulnerability, related to the
'BrokerAccessPolicyRule' policy rule. 

Note that this vulnerability only affects installations that have been
upgraded from XenDesktop 5.  Also, Nessus has not checked if any
workarounds have been applied."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX138627");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX139335");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Citrix XenDesktop 7.1 or see the vendor's advisory for
instructions on how to reset the BrokerAccessPolicyRule settings."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/04");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xendesktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("citrix_xendesktop_virtual_agent_ctx135813.nasl");
  script_require_keys("SMB/Citrix_XenDesktop/Installed", "Settings/ParanoidReport");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Citrix_XenDesktop/Installed");

# this could generate false positives due to customers having custom rules
if(report_paranoia < 2)  audit(AUDIT_PARANOID);

appname = 'Citrix XenDesktop';

port = kb_smb_transport();

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

posh_path_key = "SOFTWARE\Citrix\XenDesktopPoShModule\InstallLocation";
posh_path = get_registry_value(handle:handle, item:posh_path_key);

RegCloseKey(handle:handle);

if (isnull(posh_path) || posh_path == "")
{
  close_registry();
  audit(AUDIT_NOT_INST, appname + " Powershell Module");
}
close_registry(close:FALSE);

exe = hotfix_append_path(path:posh_path, value:'Common.dll');

res = hotfix_get_fversion(path:exe);

hotfix_handle_error(error_code:res['error'],
                    file:exe,
                    appname:appname + " Powershell Module",
                    exit_on_fail:TRUE);

version = res['value'];
disp_version = join(sep:'.', version);

hotfix_check_fversion_end();

if (version[0] == 7 && version[1] == 0)
{
  if (report_verbosity > 0)
  {
    report = '\n  Installed version : ' + disp_version +
             '\n  Fixed version     : 7.1\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_VER_NOT_VULN, appname);
