#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59310);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/05 23:13:28 $");

  script_bugtraq_id(53663);
  script_osvdb_id(82138);

  script_name(english:"Citrix XenApp Unspecified Remote DoS (CTX133159) (credentialed check)");
  script_summary(english:"Checks version of wdica.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
denial of service vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Citrix XenApp (formerly Citrix Presentation Server)
installed on the remote Windows host is potentially affected by an
unspecified denial of service vulnerability.");

  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX133159");
  script_set_attribute(attribute:"solution", value:"Apply the relevant vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 
  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:xenapp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

port    = kb_smb_transport();
login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();

appname = 'Citrix XenApp';

function display_dword (dword, nox)
{
  local_var tmp;

  if (isnull(nox) || (nox == FALSE))
    tmp = "0x";
  else
    tmp = "";

  return string (tmp,
                toupper(
                  hexstr(
                    raw_string(
                               (dword >>> 24) && 0xFF,
                               (dword >>> 16) && 0xFF,
                               (dword >>> 8) & 0xFF,
                               dword & 0xFF
                              )
                    )
                  )
                );
}

winver = get_kb_item_or_exit('SMB/WindowsVersion');
arch   = get_kb_item_or_exit('SMB/ARCH');

registry_init();
handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Make sure the software is installed and 
# get the path
xaver = NULL;
xapath = NULL;

# Make sure Xenapp is installed
prod = NULL;
item = "SOFTWARE\Citrix\XenApp\Commands\Install";
if (!isnull(get_registry_value(handle:handle, item:item)))
{
  prod = 'Citrix XenApp';
}
item = "SOFTWARE\Citrix\Install\Location";
xapath = get_registry_value(handle:handle, item:item);
if (isnull(xapath))
{
  item = "SOFTWARE\Wow6432Node\Citrix\Install\Location";
  xapath = get_registry_value(handle:handle,item:item);
}
RegCloseKey(handle:handle);

if (isnull(xapath))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
else close_registry(close:FALSE);

share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:xapath);
sys = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\Drivers\wdica.sys", string:xapath);

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
      if (isnull(prod))
        prod = data['ProductName'];
      prodver = data['ProductVersion'];
    }
    else
    {
      data = stringfileinfo[toupper(translation)];
      if (!isnull(data))
      {
        if (isnull(prod))
          prod = data['ProductName'];
        prodver = data['ProductVersion'];
      }
    }
  }
}

if (isnull(prod)) exit(1, 'Couldn\'t determine the product name from the registry or from ' + (share - '$') + ':' + sys);
if (isnull(prodver)) exit(1, 'Couldn\'t determine the product version from ' + (share - '$') + ':' + sys);

version = join(ver, sep:'.');

fix = NULL;
if (winver == '5.2' && 'Citrix Presentation Server' >< prod && prodver =~ '^4\\.5$')
{
  if (arch == 'x86')
    fix = '4.5.4655.1';
  else
    fix = '4.5.4645.1';
}
else if (winver == '6.0' && 'Citrix XenApp' >< prod && prodver =~ '^5\\.0$')
{
  if (arch == 'x86')
    fix = '5.0.6462.0';
  else
    fix = '5.0.6459.0';
}
else if (winver == '6.1' && 'Citrix XenApp' >< prod)
{
  if (prodver =~ '^6\\.0$')
    fix = '6.0.500.10161';
  else if (prodver =~ '^6\\.5$')
    fix = '6.2.26.598';
}

if (fix)
{
  if (ver_compare(ver:version, fix:fix) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  File              : ' + (share - '$') + ':' + sys +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fix + '\n';
      security_warning(port:port, extra:report);
    }
    else security_warning(port:port);
    exit(0);
  }
}
exit(0, 'No vulnerable installs of Citrix XenApp or Citrix Presentation Server were found on the remote host.');
