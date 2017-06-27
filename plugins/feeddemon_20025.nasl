#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22414);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:31:54 $");

  script_cve_id("CVE-2006-4710");
  script_bugtraq_id(20114);
  script_osvdb_id(28959);

  script_name(english:"FeedDemon < 2.0.0.25 Atom Feed Active Script Code Execution");
  script_summary(english:"Checks the version of FeedDemon.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows application may allow execution of arbitrary Active
Script code.");
  script_set_attribute(attribute:"description", value:
"According to the Windows registry, the version of FeedDemon, an RSS
reader for Windows, installed on the remote host is affected by a flaw
due to improper sanitization of RSS feeds of Active Script code. An
attacker can exploit this issue to inject arbitrary script into the
affected application, which can lead to various cross-site scripting
attacks.");
  script_set_attribute(attribute:"see_also", value:"http://nick.typepad.com/blog/2006/08/feed_security_a_1.html");
  script_set_attribute(attribute:"see_also", value:"http://nick.typepad.com/blog/2006/08/ann_feeddemon_2.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to FeedDemon version 2.0.0.25 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");
include("misc_func.inc");

# Connect to the appropriate share.
get_kb_item_or_exit("SMB/Registry/Enumerated");
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
  exit(0, "cannot connect to the remote registry");
}


# Determine location of the install.
path = NULL;
key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\FeedDemon.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) path = item[1];
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Check version of FeedDemon.exe
share = ereg_replace(pattern:"(^[A-Za-z]):.*", replace:"\1$", string:path);

if (
  is_accessible_share(share:share) &&
  hotfix_check_fversion(file:"FeedDemon.exe", path:path, version:"2.0.0.25") == HCF_OLDER
)
{
  security_warning(port);
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
