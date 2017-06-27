#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11304);
 script_version("$Revision: 1.44 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0186", "CVE-2002-0187");
 script_bugtraq_id(5004, 5005);
 script_osvdb_id(5343, 5347);
 script_xref(name:"CERT", value:"811371");
 script_xref(name:"MSFT", value:"MS02-030");
 script_xref(name:"MSKB", value:"321911");

 script_name(english:"MS02-030: Unchecked Buffer in SQLXML (321911)");
 script_summary(english:"Checks for SQLXML");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
SQL server.");
 script_set_attribute(attribute:"description", value:
"The remote host is running SQLXML. There are flaws in this application
that could allow a remote attacker to execute arbitrary code on this
host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-030");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000 and XP.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/06/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/06/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/02");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2017 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("netbios_name_get.nasl",
 		     "smb_login.nasl","smb_registry_full_access.nasl",
		     "mssql_version.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS02-030';
kb = '321911';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

ver_list = get_kb_list("mssql/installs/*/SQLVersion");

if (isnull(ver_list))
   audit(AUDIT_NOT_INST, "Microsoft SQL Server");

# SP3 applied - don't know the version number yet
#if(ereg(pattern:"[8-9]\.00\.([8-9][0-9][0-9]|7[67][0-9])", string:version))exit(0);

access = get_kb_item_or_exit("SMB/registry_full_access");

login	= kb_smb_login();
pass	= kb_smb_password();
domain  = kb_smb_domain();
port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (r != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if ( isnull(hklm) )
{
 NetUseDel();
 audit(AUDIT_REG_FAIL);
}

key = "SYSTEM\CurrentControlSet\Services\SQLXML\Performance";
item = "Library";

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if ( ! isnull(key_h) )
{
  value = RegQueryValue(handle:key_h, item:item);
  if (!isnull (value))
  {
    vuln = FALSE;
    # If it's SQL Server Gold, then issue an alert.
    foreach item (keys(ver_list))
    {
      version = get_kb_item(item);

      if (version !~ "^8\.") continue;

      key = "SOFTWARE\Microsoft\Updates\DataAccess\Q321858";
      key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
      if ( isnull(key_h2) )
      {
        vuln = TRUE;
        set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
        report = '\nThe following registry key is missing :\n'+
                 'is missing :\n\n'+
                 '  HKEY_LOCAL_MACHINE\\'+key+'\n\n'+
                 'which indicates the relevant patch has not been applied.\n';
        hotfix_add_report(report, bulletin:bulletin, kb:kb);
        hotfix_security_warning();
      }
      else RegCloseKey (handle:key_h2);
      break;
    }

    if(!vuln)
    {
      # SQLXML 2.0
      if(ereg(pattern:".*sqlxml2\.dll", string:value))
      {
        key = "SOFTWARE\Microsoft\Updates\SQLXML 2.0\Q321460";
        key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if ( isnull(key_h2) )
        {
          set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
          report = '\nThe following registry key is missing :\n'+
                   'is missing :\n\n'+
                   '  HKEY_LOCAL_MACHINE\\'+key+'\n\n'+
                   'which indicates the relevant patch has not been applied.\n';
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          hotfix_security_warning();
        }
        else
          RegCloseKey (handle:key_h2);
      }

      # SQLXML 3.0
      else if(ereg(pattern:".*sqlxml3\.dll", string:value))
      {
        key = "SOFTWARE\Microsoft\Updates\SQLXML 3.0\Q320833";
        key_h2 = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
        if ( isnull(key_h2) )
        {
          set_kb_item(name:"SMB/Missing/MS02-030", value:TRUE);
          report = '\nThe following registry key is missing :\n'+
                   'is missing :\n\n'+
                   '  HKEY_LOCAL_MACHINE\\'+key+'\n\n'+
                   'which indicates the relevant patch has not been applied.\n';
          hotfix_add_report(report, bulletin:bulletin, kb:kb);
          hotfix_security_warning();
        }
        else
          RegCloseKey (handle:key_h2);
      }
    }
  }
  RegCloseKey (handle:key_h);
}

RegCloseKey (handle:hklm);
NetUseDel ();


