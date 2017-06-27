#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(24670);
  script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2016/10/10 15:57:04 $");

  script_cve_id("CVE-2007-0324");
  script_bugtraq_id(22569);
  script_osvdb_id(33199);

  script_name(english:"DjVu Browser Plug-in < 6.1.1 Multiple Buffer Overflows");
  script_summary(english:"Checks for DjVu Browser Plug-in < 6.1.1");

 script_set_attribute(attribute:"synopsis", value:
"A browser plugin on the remote Windows host is affected by multiple
buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The DjVu Browser Plug-in is installed on the remote Windows host. This
plugin provides the primary means of viewing DjVu documents, which are
used for publishing scanned books, catalogs, historical documents,
research papers, manuals, etc.

The version of the DjVu Browser Plug-in installed on the remote host
reportedly is affected by several buffer overflows involving various
functions. An attacker may be able to leverage these issues to execute
arbitrary code on the remote host subject to the user's privileges if
the user can be tricked into viewing a specially crafted web page.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Feb/348" );
 # http://web.archive.org/web/20070217223628/http://www.lizardtech.com/products/doc/djvupluginrelease.php
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae522049" );
 script_set_attribute(attribute:"solution", value:"Upgrade to DjVu Browser Plug-in version 6.1.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/19");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(0);

#session_init(socket:soc, hostname:name);
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


# Determine where it's installed.
path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\DjVuCntl.dll";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(value)) path = value[1];

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If we found the path...
if (path)
{
  # Determine its version from the DLL itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\DjVuCntl.dll", string:path);
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
  ver = NULL;
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 6.1.1.1574
  if (!isnull(ver))
  {
    fix = split("6.1.1.1574", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = strcat(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = strcat('\nVersion ', version, ' of the DjVu Browser Plug-in is installed under :\n\n ', path);
        security_hole(port:port, extra: report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();
