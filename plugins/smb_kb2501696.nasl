#
# (C) Tenable Network Security, Inc.
#
# @DEPRECATED@
#

include('compat.inc');

if (description)
{
  script_id(51837);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/04/25 17:36:44 $");

  script_cve_id("CVE-2011-0096");
  script_bugtraq_id(46055);
  script_osvdb_id(70693);
  script_xref(name:"Secunia", value:"43093");

  script_name(english:"MS KB2501696: Vulnerability in MHTML Could Allow Information Disclosure");
  script_summary(english:"Checks for workaround");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");

  script_set_attribute(attribute:"description", value:
"A flaw exists in the way MHTML interprets MIME-formatted requests for
content blocks within a document.  An attacker, exploiting this flaw,
could cause a victim to run malicious scripts when visiting various
websites, resulting in information disclosure.");

  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2501696");

  script_set_attribute(attribute:"solution", value:
"Consider applying the workaround provided by Microsoft. 

Note, though, that applying the workaround may lead to some websites
working incorrectly.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

# This script has been disabled and is intended to be blank.
# Disabled on 2011/04/12. Deprecated by smb_nt_ms11-026.nasl.
exit(0, "Deprecated - replaced by smb_nt_ms11-026.nasl");

include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
arch = get_kb_item_or_exit("SMB/ARCH", exit_code:1);

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:1) <= 0) exit(0, 'The host is not affected based on its version / service pack.');
if (hotfix_check_server_core() == 1) exit(0, 'Windows Server Core installs are note affected.');

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) exit(1, 'Port '+port+' is not open.');
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

session_init(socket:soc, hostname:name);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to the remote registry
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to the remote registry.");
}

# First check if MHTML Protocol lockdown is enabled
vuln = FALSE;

key = "SOFTWARE\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_PROTOCOL_LOCKDOWN";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:'explorer.exe');
  if (isnull(value) || value[1] == 0) vuln = TRUE;

  value = RegQueryValue(handle:key_h, item:'iexplore.exe');
  if (isnull(value) || value[1] == 0) vuln = TRUE;

  if (!vuln)
  {
    # Check that the restricted protocol is mhtml
    keys = make_list(
      "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\1",
      "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\2",
      "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\3",
      "SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\4"
    );
    foreach key2 (keys)
    {
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h)) 
      {
        value = RegQueryValue(handle:key2_h, item:'mhtml');
        if (isnull(value) || value[1] != 'mhtml') vuln = TRUE;
      }
      else vuln = TRUE;
      RegCloseKey(handle:key2_h);
    }
  }
  RegCloseKey(handle:key_h);
}
# If the architecture is x64, also check the Wow6432 node if necessary.
if (!vuln && arch == 'x64')
{
  key = "SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\MAIN\FeatureControl\FEATURE_PROTOCOL_LOCKDOWN";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:'explorer.exe');
    if (isnull(value) || value[1] == 0) vuln = TRUE;
  
    value = RegQueryValue(handle:key_h, item:'iexplore.exe');
    if (isnull(value) || value[1] == 0) vuln = TRUE;
  
    if (!vuln)
    {
      # Check that the restricted protocol is mhtml
      keys = make_list(
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\1",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\2",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\3",
        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\RestrictedProtocols\4"
      );
      foreach key2 (keys)
      {
        key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
        if (!isnull(key2_h)) 
        {
          value = RegQueryValue(handle:key2_h, item:'mhtml');
          if (isnull(value) || value[1] != 'mhtml') vuln = TRUE;
        }
        else vuln = TRUE;
        RegCloseKey(handle:key2_h);
      }
      RegCloseKey(handle:key_h);
    }
  }
}

RegCloseKey(handle:hklm);
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n' + 'Nessus determined the workaround was not applied because MHTML has not' +
      '\n' + 'been added as a restricted protocol.\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
exit(0, "The host is not affected because the MHTML protocol has been locked down.");
