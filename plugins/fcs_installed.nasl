#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43164);
  script_version("$Revision: 1.1004 $");
  script_cvs_date("$Date: 2015/09/24 21:08:39 $");

  script_name(english:"Microsoft Forefront Client Security Unsupported");
  script_summary(english:"Checks if Forefront Client Security is installed.");

  script_set_attribute(attribute:"synopsis", value:
"An antivirus program that is no longer supported is installed on the
remote host.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Microsoft Forefront
Client Security on the remote host is no longer supported.

Lack of support implies that no new security patches for the product
will be released by the vendor. As a result, it is likely to contain
security vulnerabilities.");
  # https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Forefront%20Client%20Security&Filter=FilterNO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?871435c9");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/ff823816.aspx");
  script_set_attribute(attribute:"solution", value:
"Migrate to a different antivirus product.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"unsupported_by_vendor", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl","smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Services/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/Services/Enumerated");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

path = NULL;
avsignatures = NULL;
assignatures = NULL;
engine_version = NULL;
key2 = NULL;

# Find where it's installed.

key = "SOFTWARE\Microsoft\Microsoft Forefront\Client Security";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey + "\AM";
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallLocation");
        if (!isnull(value)) path = value[1];

        RegCloseKey(handle:key2_h);
        if(!isnull(path)) break;
      }
    }
  }
  RegCloseKey (handle:key_h);
}

if ( isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "Forefront Client Security");
}

if (isnull(key2))
{
  # We shouldn't ever get here, but if we do...
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(1, "Variable key2 was set to NULL.");
}
else
  key = key2 + '\\Signature Updates';

# Get the Antivirus/AntiSpyware Signature and Engine version.

key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"AVSignatureVersion");
  if (!isnull(value)) avsignatures = value[1];

  value = RegQueryValue(handle:key_h, item:"ASSignatureVersion");
  if (!isnull(value)) assignatures = value[1];

   value = RegQueryValue(handle:key_h, item:"EngineVersion");
  if (!isnull(value)) engine_version = value[1];

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

# Grab the file version of file MSASCui.exe

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\MSASCui.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

ver  = NULL;
pname = NULL;

if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
      {
        ver  = data['FileVersion'];
        pname    = data['ProductName'];
      }
    }
  }
  CloseFile(handle:fh);
}

NetUseDel();

report = NULL;

if(!isnull(ver))
{
  set_kb_item(name:"Antivirus/Forefront_Client_Security/installed", value:TRUE);
  set_kb_item(name:"Antivirus/Forefront_Client_Security/version", value:ver);
  set_kb_item(name:"Antivirus/Forefront_Client_Security/path", value:path);

  register_install(
    app_name:"Forefront Client Security",
    path:path,
    version:ver,
    extra:make_array("engine_version", engine_version,"av_sigs", avsignatures,"as_sigs", assignatures));

  register_unsupported_product(
    product_name:"Forefront Client Security",
    version:ver,
    cpe_base:"microsoft:forefront_client_security");

  if (isnull(pname))
    pname = 'Microsoft Forefront Client Security';

  report = '\n' +
           "Microsoft Forefront Client Security is installed on the remote host : " + '\n'+
           '\n' +
           "Product name : "      + pname + '\n' +
           "Installation path : " + path + '\n' +
           "Version : "           + ver ;

   if(!isnull(engine_version))
  {
    set_kb_item(name:"Antivirus/Forefront_Client_Security/engine_version", value:engine_version);
    report += '\n' +
              'Engine version : ' + engine_version ;
  }

  if(!isnull(avsignatures))
  {
    set_kb_item(name:"Antivirus/Forefront_Client_Security/av_sigs", value:avsignatures);
    report += '\n' +
              'Antivirus signature version : ' + avsignatures ;
  }

  if(!isnull(assignatures))
  {
    set_kb_item(name:"Antivirus/Forefront_Client_Security/as_sigs", value:assignatures);
    report += '\n' +
              'Antispyware signature version : ' + assignatures ;
  }

  report += '\n';
}
else
{
  audit(AUDIT_UNINST, "Forefront Client Security");
}

# If we're here, it's installed and has a version we can parse.
report += '\n\n' +
    "Support for Forefront Client Security was discontinued on 2015/07/14." + '\n\n' +
    "No new security patches for the product will be released by the" + '\n\n' +
    "vendor. As a result, it is likely to contain security" + '\n\n' +
    "vulnerabilities." + '\n';
security_hole(port:port, extra:'\n'+report);
