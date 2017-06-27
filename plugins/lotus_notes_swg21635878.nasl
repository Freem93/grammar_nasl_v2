#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66944);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2013-2977");
  script_bugtraq_id(59693);
  script_osvdb_id(93057);

  script_name(english:"IBM Notes PNG Integer Overflow");
  script_summary(english:"Checks version of notes");

  script_set_attribute(attribute:"synopsis", value:
"The version of IBM Notes installed on the remote Windows host is
affected by an integer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The IBM Notes application installed on the remote Windows host is 8.5
earlier than Fix Pack 4 Interim Fix 1, or 9.0 earlier than Interim Fix
1. It is, therefore, potentially affected by an integer overflow
vulnerability. By exploiting this flaw, a remote, unauthenticated
attacker could execute arbitrary code on the remote host subject to
the privileges of the user running the affected application.");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_notes_png_integer_overflow_cve_2013_29771?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f0e51732");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21635878");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Notes 8.5.3 Fix Pack 4 / 9.0 Interim Fix 1 or apply the
workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "lotus_notes_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

appname = 'IBM Lotus Notes';
kb_base = 'SMB/Lotus_Notes';

version = get_kb_item_or_exit(kb_base + '/Version');
ver_ui = get_kb_item_or_exit(kb_base + '/Version_UI');
apppath = get_kb_item_or_exit(kb_base + '/Path');

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:apppath);
share = hotfix_path2share(path:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}


vuln = FALSE;
ver = split(version, sep:'.', keep:FALSE);
for (i=0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

fix = '';
if (version =~ '^8\\.5\\.' && ver_compare(ver:version, fix:'8.5.34.13086') < 0)
{
  vuln = TRUE;
  fix = '8.5.34.13086';
}
else if (ver[0] == 9)
{
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\nsd.exe", string:apppath);
  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    audit(AUDIT_VER_FAIL, exe);
  }
  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);
  if (!isnull(ret))
  {
    timestamp = ret['dwTimeDateStamp'];
  }
  if (isnull(timestamp))
    exit(1, 'Failed to get the timestamp of ' + apppath + "\nsd.exe.");
  if (timestamp < 1367003838)
  {
    fixtimestamp = 1367003838;
    vuln = TRUE;
  }
}
if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + apppath +
      '\n  Installed version : ' + version;
    if (fixtimestamp)
    {
      report +=
        '\n  File             : ' + apppath + "\nsd.exe" +
        '\n  File Timestamp   : ' + timestamp +
        '\n  Fixed Timestamp  : ' + fixtimestamp + '\n';
    }
    else
      report += '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, apppath);
