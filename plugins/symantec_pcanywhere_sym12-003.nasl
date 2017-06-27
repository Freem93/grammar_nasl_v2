#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(58204);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/01/12 17:12:49 $");

  script_cve_id("CVE-2012-0292");
  script_bugtraq_id(52094);
  script_osvdb_id(79412);
  script_xref(name:"EDB-ID", value:"18493");

  script_name(english:"Symantec pcAnywhere awhost32 Denial of Service (SYM12-003)");
  script_summary(english:"Checks version of aw32tcp.dll");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a denial of
service vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Symantec pcAnywhere installed on the remote host is
potentially affected by a denial of service vulnerability. Unexpected
input to the awhost32 service could destabilize the service, causing
it to crash.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?671e3799");
  script_set_attribute(attribute:"solution", value:
"Apply the hotfix referenced in the Symantec advisory or upgrade to
pcAnywhere 12.5 SP4, pcAnywhere Solution 12.6.7, or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("symantec_pcanywhere_installed.nasl");
  script_require_keys("SMB/Symantec pcAnywhere/Path", "SMB/Symantec pcAnywhere/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('audit.inc');

path = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Path');
version = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Version');
build = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Build');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# The hotfix is only available for version 12.x
if (ver[0] == 12)
{
  # Connect to the appropriate share
  name   = kb_smb_name();
  port   = kb_smb_transport();
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();



  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  dll   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\aw32tcp.dll', string:path);

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
  }

  # Check the version of aw32tcp.dll
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, 'Couldn\'t open \''+(share-'$')+':'+dll+'\'.');
  }

  dllver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel();

  if (isnull(dllver)) exit(1, 'Couldn\'t get the version \''+(share-'$')+':'+dll+'\'.');
  for (i=0; i<max_index(dllver); i++)
    dllver[i] = int(dllver[i]);

  dllversion = join(dllver, sep:'.');

  fix = NULL;
  if (ver[1] == 5)
  {
    if (ver[2] == 1 && (build == 486))
      fix = '12.5.1.525';
    else if (ver[2] == 0 && (build == 463 || build == 442))
      fix = '12.5.0.484';
    else if (ver[2] == 0 && build == 265)
      fix = '12.5.0.304';
  }
  else if (ver[1] == 1)
  {
    if (ver[2] == 0 && (build == 446))
      fix = '12.1.0.473';
  }
  else if (ver[1] == 0)
  {
    if (ver[2] == 2 && build == 174)
      fix = '12.0.3.405';
    else if (ver[2] == 1 && build == 156)
      fix = '12.0.3.405';
  }

  if (fix)
  {
    if (ver_compare(ver:dllversion, fix:fix) == -1)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Path              : ' + path +
          '\n  Affected DLL      : ' + dll +
          '\n  Installed version : ' + dllversion +
          '\n  Fixed version     : ' + fix + '\n';
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
    else exit(0, 'The pcAnywhere '+version+' Build '+build+' install in '+path+' has aw32tcp.dll '+dllversion+' and thus is not affected.');
  }
}
exit(0, 'The pcAnywhere '+version+' Build '+build+' install in '+path+' is not affected.');
