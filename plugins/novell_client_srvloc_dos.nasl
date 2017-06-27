#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23970);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2006-6307");
  script_bugtraq_id(21430);
  script_osvdb_id(31354);

  script_name(english:"Novell Client srvloc.sys Crafted Packet Unspecified Remote DoS");
  script_summary(english:"Checks file versions of srvloc.sys / nwgina.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a service that is susceptible to a
denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The file 'srvloc.sys' included with the Novell Client software is
reportedly vulnerable to a denial of service attack when processing
malformed SLP packets to port 427.

Note that it is not currently known whether this involves the TCP or
UDP service or both.");

  script_set_attribute(attribute:"solution", value:"Upgrade to Novell Client 4.91 SP3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

# Unless we're being paranoid, check whether the software's installed.
if (report_paranoia < 2)
{
  subkey = "{Novell Client for Windows}";
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  get_kb_item_or_exit(key);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Check the version of srvloc.sys.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\Netware\srvloc.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

fh = CreateFile(
  file:sys,
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


# NB: make sure the version is 4.91.3.0, which is true of 4.91 Support
#     Pack 2 w/ 491psp2_pkc.exe.  For some reason, Novell didn't update
#     the file version when it changed this for SP3, so we have to rely
#     another file which did change between them; eg, nwgina.dll.
if (
  !isnull(ver) &&
  int(ver[0]) == 4 && int(ver[1]) == 91 && int(ver[2]) == 3 && int(ver[3]) == 0
)
{
  file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\nwgina.dll", string:winroot);
  fh = CreateFile(
    file:file,
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

  # File version is 4.91.1.36 w/ SP3.
  if (!isnull(ver))
  {
    fix = split("4.91.1.36", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        security_warning(port);
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}


# Clean up.
NetUseDel();

