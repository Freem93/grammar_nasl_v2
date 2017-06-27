#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42879);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/18 20:40:53 $");

  script_cve_id("CVE-2009-3840", "CVE-2010-2710");
  script_bugtraq_id(37046, 42636);
  script_osvdb_id(60200, 67328);
  script_xref(name:"Secunia", value:"37376");
  script_xref(name:"HP", value:"emr_na-c01926980");
  script_xref(name:"HP", value:"HPSBMA02477");
  script_xref(name:"HP", value:"SSRT090177");
  script_xref(name:"EDB-ID", value:"10176");

  script_name(english:"HP OpenView Network Node Manager Multiple Vulnerabilities");
  script_summary(english:"Does a version check on ovdbrun.exe.");

  script_set_attribute(attribute:"synopsis", value:
"A database service on the remote Windows host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of HP OpenView Network Node Manager (NNM) installed on the
remote Windows host is affected by multiple vulnerabilities :

  - The embedded DB service is affected by a denial of
    service vulnerability that is triggered when it receives
    a packet with an error code of less than -1. An
    unauthenticated, remote attacker can exploit this to
    crash the service. (CVE-2009-3840)

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to execute arbitrary
    code. No other details are available. (CVE-2010-2710)

This plugin only checks OpenView NNM running on Windows, though other
platforms are affected.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2009/Nov/199");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c01926980
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f5658b3");
  script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_network_node_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_ports(139, 445, 2690);
  script_require_keys("SMB/login", "SMB/password", "SMB/name", "SMB/transport", "SMB/Registry/Enumerated");

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");
include("misc_func.inc");

svc_name = 'HP OpenView NNM Embedded DB';
svc_running = get_kb_item('SMB/svc/' + svc_name);

if (isnull(svc_running))
  exit(0, 'The SMB/svc/'+svc_name+' KB item is missing.');

if (svc_running != SERVICE_ACTIVE && report_paranoia < 2)
  exit(0, 'The ' + svc_name + ' service is not running.');

get_kb_item_or_exit("SMB/Registry/Enumerated");

name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

path = NULL;
exe = NULL;
ovdbrun_key = "SOFTWARE\ovdbrun\ovdbrun\7.50";
ovdbrun_key_h = RegOpenKey(handle:hklm, key:ovdbrun_key, mode:MAXIMUM_ALLOWED);

if (!isnull(ovdbrun_key_h))
{
  item = RegQueryValue(handle:ovdbrun_key_h, item:"exe");

  if (!isnull(item))
  {
    path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:item[1]);
    exe = ereg_replace(pattern:"^.+\\([^\\]+)$", replace:"\1", string:item[1]);
  }

  RegCloseKey (handle:ovdbrun_key_h);
}

RegCloseKey(handle:hklm);
NetUseDel();

if (isnull(path))
  exit(0, "Can't find evidence of ovdbrun in the registry.");

if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

if (hotfix_is_vulnerable(file:exe, version:"4.50.0.169", path:path))
{
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

