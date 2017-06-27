#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(29899);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2008-6061");
  script_bugtraq_id(27107);
  script_osvdb_id(40102);
  script_xref(name:"CERT", value:"249337");

  script_name(english:"Camtasia Studio Pre-generated SWF File csPreloader Parameter Unspecified Arbitrary Code Execution");
  script_summary(english:"Checks version of CamtasiaStudio.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that reportedly allows
arbitrary code execution.");
 script_set_attribute(attribute:"description", value:
"Camtasia Studio, an application for recording videos, is installed on
the remote host.

The version of Camtasia Studio on the remote host reportedly generates
Flash (SWF) files that themselves allow loading of an arbitrary Flash
file via the 'csPreloader' parameter, which could lead to cross-site
scripting attacks against a web server hosting vulnerable SWF files or
even execution of arbitrary code on a user's system.");
 script_set_attribute(attribute:"see_also", value:"http://docs.google.com/Doc?docid=ajfxntc4dmsq_14dt57ssdw");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485722" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Camtasia Studio 5.0 or later as that reportedly resolves
the issue and regenerate SWF content. Note that upgrading by itself is
not sufficient to resolve this issue.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/10");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
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


# Make sure it's installed.
exes = make_array();

key = "SOFTWARE\TechSmith\Camtasia Studio";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = key + "\" + subkey;
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallExe");
        if (!isnull(value)) exes[value[1]]++;
        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (max_index(keys(exes)) == 0)
{
  NetUseDel();
  exit(0);
}


# Grab the file version of the exe.
foreach exe (keys(exes))
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);

  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:exe2,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }
  NetUseDel();

  # Check the version number.
  if (!isnull(ver))
  {
    fix = split("5.0.0.0", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        path = ereg_replace(pattern:"^(.+)\\\[^\]+\.exe$", replace:"\1", string:exe);

        report = string(
          "Version ", version, " of Camtasia Studio is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_warning(port:port, extra:report);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
