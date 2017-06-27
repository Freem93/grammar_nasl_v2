#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(47045);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 20:54:58 $");

  script_cve_id("CVE-2010-1885", "CVE-2010-2265");
  script_bugtraq_id(40721, 40725);
  script_osvdb_id(65264, 65529);
  script_xref(name:"CERT", value:"578319");
  script_xref(name:"IAVA", value:"2010-A-0095");
  script_xref(name:"MSFT", value:"MS10-042");

  script_name(english:"MS KB2219475: Windows Help Center hcp:// Protocol Handler Arbitrary Code Execution");
  script_summary(english:"Checks whether the hcp protocol has been unregistered");

  script_set_attribute(attribute:"synopsis", value:
"It may be possible to execute arbitrary code on the remote host using
Windows Help and Support Center.");
  script_set_attribute(attribute:"description", value:
"If a remote attacker can trick a user on the affected host into
accessing a malicious web page containing specially crafted 'hcp://'
URLs, an as-yet unpatched vulnerability in Windows Help and Support
Center that arises due to its failure to validate URLs that use the
HCP protocol could be leveraged to execute arbitrary code on the host
subject to the user's privileges.");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2010/Jun/205"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/advisory/2219475"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-042"
  );
  script_set_attribute(attribute:"solution", value:
"Either apply MS10-042 or consider unregistering the HCP protocol as a
workaround.

Note, though, that applying the workaround will break local,
legitimate help links that use 'hcp://'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft Help Center XSS and Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_nt_ms10-042.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/Missing/MS10-042");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");


if (!get_kb_item('SMB/WindowsVersion')) exit(1, "The 'SMB/WindowsVersion' KB item is missing.");
if (hotfix_check_sp(xp:4, win2003:3) <= 0) exit(0, "The host is not affected based on its version / service pack.");
if (!get_kb_item("SMB/Missing/MS10-042")) exit(0, "The host is not affected because the 'SMB/Missing/MS10-042' KB item is missing.");


# Connect to the appropriate share.
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

hkcr = RegConnectRegistry(hkey:HKEY_CLASS_ROOT);
if (isnull(hkcr))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}


hcp_installed = FALSE;
hcp_label = "";
hcp_handler = "";

key = "HCP";
key_h = RegOpenKey(handle:hkcr, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # nb: per <http://msdn.microsoft.com/en-us/library/aa767914%28VS.85%29.aspx>,
  #     the "URL Protocol" string must be present.
  value = RegQueryValue(handle:key_h, item:"URL Protocol");
  if (!isnull(value))
  {
    hcp_installed = TRUE;

    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) hcp_label = value[1];

    key2 = key + "\shell\open\command";
    key2_h = RegOpenKey(handle:hkcr, key:key2, mode:MAXIMUM_ALLOWED);
    if (!isnull(key2_h))
    {
      value = RegQueryValue(handle:key2_h, item:NULL);
      if (!isnull(value)) hcp_handler = value[1];

      RegCloseKey(handle:key2_h);
    }
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hkcr);
NetUseDel();


if (hcp_installed)
{
  if (hcp_handler)
  {
    if (report_verbosity > 0)
    {
      if (!hcp_label) hcp_label = 'n/a';

      report = '\n  Label   : ' + hcp_label +
               '\n  Handler : ' + hcp_handler + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  else exit(0, "The HCP protocol handler has been unregistered.");
}
else exit(0, "The HCP protocol handler has been deleted.");
