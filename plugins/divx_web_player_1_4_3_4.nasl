#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(36185);
  script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2008-5259");
  script_bugtraq_id(34523);
  script_osvdb_id(53689);
  script_xref(name:"Secunia", value:"33196");

  script_name(english:"DivX Web Player < 1.4.3.4 Stream Format Chunk Buffer Overflow");
  script_summary(english:"Checks version of npdivx32.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is susceptible to
a buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"DivX Web Player, which allows for playing HD-quality DivX video in a
web browser, is installed on the remote host.

The installed version contains a heap-based buffer overflow that is
triggered when processing 'STRF' (Stream Format) chunks. Using a
specially crafted DivX file, an attacker may be able to leverage this
issue to execute arbitrary code on the host subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2008-57/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to DivX Web Player 1.4.3.4 or later in an updated DivX bundle
as that reportedly addresses the issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(189);

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i<l; i++)
    res += str[i] + null;

  return res;
}


# Detect where it's installed.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
if (isnull(list)) exit(0);
key = NULL;
foreach name (keys(list))
{
  prod = list[name];
  if (prod && prod =~ "^DivX Web Player")
  {
    key = ereg_replace(pattern:"^SMB\/Registry\/HKLM\/(.+)\/DisplayName$", replace:"\1", string:name);
    key = str_replace(find:"/", replace:"\", string:key);
    break;
  }
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Find the agent's location.
path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SOFTWARE\DivXNetworks\DivXBrowserPlugin";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"SkinPath");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\[^\\]+$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
if (isnull(path))
{
  key = "SOFTWARE\MozillaPlugins\@divx.com/DivX Browser Plugin,version=1.0.0";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Path");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:"^(.+)\\[^\\]+\.dll$", replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Grab the version from npdivx32.dll
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\npdivx32.dll", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
if (!isnull(fh))
{
  fsize = GetFileSize(handle:fh);
  if (fsize < 90000) off = 0;
  else off = fsize - 90000;

  vs_version_info = mk_unicode(str:"VS_VERSION_INFO");
  while (fsize > 0 && off <= fsize)
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) == 0) break;

    i = stridx(data, vs_version_info);
    if (i >= 0)
    {
      off += i;
      table = ReadFile(handle:fh, length:1024, offset:off);

      fileversion = mk_unicode(str:"FileVersion");
      if (fileversion >< table)
      {
        i = stridx(table, fileversion) + strlen(fileversion);
        while (i<strlen(table) && !ord(table[i])) i++;
        while (i<strlen(table) && ord(table[i]))
        {
          version += table[i];
          i += 2;
        }
        version = str_replace(find:" ", replace:"", string:version);
        version = str_replace(find:",", replace:".", string:version);
      }
      break;
    }
    else off += 16383;
  }

  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(version))
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("1.4.3.4", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report = string(
          "\n",
          "Nessus collected the following information about the remote DivX Web\n",
          "Player installation :\n",
          "\n",
          "  Version : ", version, "\n",
          "  Path    : ", path, "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
