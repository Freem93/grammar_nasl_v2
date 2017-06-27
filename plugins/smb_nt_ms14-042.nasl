#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76411);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2014-2814");
  script_bugtraq_id(68393);
  script_osvdb_id(108825);
  script_xref(name:"MSFT", value:"MS14-042");
  script_xref(name:"IAVB", value:"2014-B-0094");

  script_name(english:"MS14-042: Vulnerability in Microsoft Service Bus Could Allow Denial of Service (2972621)");
  script_summary(english:"Checks the version of Microsoft.ServiceBus.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Service Bus for Windows Servers installed on
the remote Windows host is affected by a denial of service
vulnerability. By sending a specially crafted Advanced Message Queuing
Protocol (AMQP) message, a remote authenticated attacker could crash
the affected service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-042");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Microsoft Service Bus 1.1.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:service_bus");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("microsoft_service_bus_for_servers_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
appname = 'Microsoft Service Bus for Windows Server';

bulletin = 'MS14-042';
kb = '2972621';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);
if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ('Windows Server 2008 R2' >!< productname && 'Small Business Server 2011' >!< productname && 'Windows Server 2012' >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

install = get_installs(app_name:appname);
if (install[0] == IF_NOT_FOUND) audit(AUDIT_NOT_INST, appname);

install = install[1][0];
version = install['version'];
path = install['path'];

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_APP_VER, appname);

if (ver_compare(ver:version, fix:'2.1.30904.0') == 0)
{
  info =
    '\n  Product           : ' + appname +
    '\n  File              : ' + path + "\Microsoft.ServiceBus.dll" +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : 2.1.40512.2' + 
    '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();

  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
