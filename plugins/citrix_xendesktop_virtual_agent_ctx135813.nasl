#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(63325);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/11/04 19:29:08 $");

  script_cve_id("CVE-2012-6314");
  script_bugtraq_id(56908);
  script_osvdb_id(88369);

  script_name(english:"Citrix XenDesktop Virtual Desktop Agent USB Redirection Propagation Handling Access Restriction Bypass (CTX135813)");
  script_summary(english:"Checks version of VdaRdpPlugIn.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a local
security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix XenDesktop Virtual Desktop Agent contains a flaw
in the server-side USB redirection policy.  This could allow an
authenticated user to gain access to their USB devices when the
server-side policy has been modified to disable USB redirection.");
  script_set_attribute(attribute:"see_also", value:"https://support.citrix.com/article/CTX135813");
  script_set_attribute(attribute:"solution", value:"Apply the relevant patch from the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xendesktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

appname = 'Citrix XenDesktop Virtual Desktop Agent';

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Make sure the software is installed and
# get the path
version = NULL;
path = NULL;

# Make sure Xenapp is installed
prod = NULL;
item = "SOFTWARE\Citrix\Install\Location";
path = get_registry_value(handle:handle, item:item);
if(isnull(path))
{
  item = "SOFTWARE\Wow6432Node\Citrix\Install\Location";
  path = get_registry_value(handle:handle, item:item);
}

RegCloseKey(handle:handle);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

set_kb_item(name:"SMB/Citrix_XenDesktop/Installed", value:TRUE);

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
sys = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1Virtual Desktop Agent\VdaRdpPlugIn.dll", string:path);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  close_registry();
  audit(AUDIT_UNINST, appname);
}

ver = GetFileVersion(handle:fh);
ret = GetFileVersionEx(handle:fh);
CloseFile(handle:fh);
close_registry();

if (isnull(ver) || isnull(ret)) audit(AUDIT_VER_FAIL, (share - '$')+':'+sys);

prodver = NULL;
children = ret['Children'];
if (!isnull(children))
{
  stringfileinfo = children['StringFileInfo'];
  # nb: if varfileinfo is missing, use the first key for the translation
  if (!isnull(stringfileinfo))
  {
    foreach translation (keys(stringfileinfo))
      break;
  }
  if (!isnull(stringfileinfo) && !isnull(translation))
  {
    data = stringfileinfo[translation];
    if (!isnull(data))
    {
      prodver = data['ProductVersion'];
    }
    else
    {
      data = stringfileinfo[toupper(translation)];
      if (!isnull(data))
      {
        prodver = data['ProductVersion'];
      }
    }
  }
}

if (isnull(prodver)) exit(1, 'Couldn\'t determine the product version from ' + (share - '$') + ':' + sys);

version = join(ver, sep:'.');

fix = '5.6.200.9';
if (prodver =~ '^5\\.[0-6]\\.')
{
  if (ver_compare(ver:version, fix:fix, strict:FALSE) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + (share - '$') + ':' + sys +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port:port);
    exit(0);
  }
}
audit(AUDIT_INST_VER_NOT_VULN, appname, version);
