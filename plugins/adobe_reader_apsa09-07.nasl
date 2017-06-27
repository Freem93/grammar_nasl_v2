#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#
# Disabled on 2010/01/13.  Replaced by the more comprehensive
# adobe_reader_apsb10-02.nasl (plugin ID 43876)

exit(0);

include("compat.inc");


if (description)
{
  script_id(43183);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/05/21 22:01:06 $");

  script_cve_id("CVE-2009-4324");
  script_bugtraq_id(37331);
  script_osvdb_id(60980);
  script_xref(name:"CERT", value:"508357");
  script_xref(name:"Secunia", value:"37690");

  script_name(english:"Adobe Reader Doc.media.newPlayer Use-After-Free Arbitrary Code Execution");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The version of Adobe Reader on the remote Windows host is affected by
a code execution vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Adobe Reader on the remote host allows execution of
arbitrary code due to a use-after-free vulnerability in the
'Doc.media.newplayer()' method, which can result in memory corruption.

A remote attacker may be able to exploit this by tricking a user into
opening a specially crafted PDF file, resulting in arbitrary code
execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.adobe.com/support/security/advisories/apsa09-07.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://kb2.adobe.com/cps/504/cpsid_50431.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"If Adobe Reader 9.2 / 8.1.7 is installed, apply the JavaScript
blacklist workaround.  If earlier versions are installed, disable
JavaScript (refer to Adobe's advisory for more information)."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/17"
  );
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Acroread/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


version = get_kb_item('SMB/Acroread/Version');
if (isnull(version)) exit(1, "The 'SMB/Acroread/Version' KB item is missing.");

name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(1, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
  
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# For 9.2 and 8.1.7, check for the JS workaround
if (
  (ver[0] == 9 && ver[1] == 2 && ver[2] == 0) ||
  (ver[0] == 8 && ver[1] == 1 && ver[2] == 7)
)
{
  soc = open_sock_tcp(port);
  if (!soc) exit(1, "Can't open a socket on port "+port+".");
  
  session_init(socket:soc, hostname:name);
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
  
  # Checks the enterprise and update/patch blacklists
  keys = make_list(
    'SOFTWARE\\Policies\\Adobe\\Acrobat Reader\\'+ver[0]+'.0\\FeatureLockDown\\cJavaScriptPerms',
    'SOFTWARE\\Adobe\\Acrobat Reader\\'+ver[0]+'.0\\JavaScriptPerms'
  );

  foreach key (keys)
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:"tBlackList");

      # If multiple blacklists are found, ensure that we check them all
      if (value && blacklist) blacklist += '|' + value[1];
      else if (value) blacklist = value[1];
    
      RegCloseKey(handle:key_h);
    }
  }

  RegCloseKey(handle:hklm);
  close(soc);

  if (isnull(blacklist) || 'DocMedia.newPlayer' >!< blacklist)
  {
    if (report_verbosity > 0)
    {
      report =
        '\nNessus did not detect a JavaScript blacklist in HKLM containing\n'+
        '"DocMedia.newPlayer".\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else exit(0, "The host is not affected.");
}

# For all earlier versions, do a version check.  Since we can't determine if
# the workaround (disable JavaScript) has been enabled on earlier versions,
# only do the version check when paranoid
if (report_paranoia < 2)
  exit(1, "This plugin only runs if 'Report paranoia' is set to 'Paranoid'.");

if
(
  (ver[0] == 9 && ver[1] < 2) ||
  (ver[0] == 8 && (ver[1] < 1 || (ver[1] == 1 && ver[2] < 7))) ||
  (ver[0] < 8 && ver[0] >= 6)  # Doc.media.newPlayer was introduced in 6.0
)
{
  version_ui = get_kb_item('SMB/Acroread/Version_UI');

  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item('SMB/Acroread/Path');
    if (isnull(path)) path = 'n/a';

    report = 
      '\n'+
      '  Product           : Adobe Reader\n'+
      '  Path              : '+path+'\n'+
      '  Installed version : '+version_ui+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The host is not affected.");
 
