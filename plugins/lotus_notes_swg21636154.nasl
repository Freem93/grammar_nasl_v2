#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66942);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2013-0534");
  script_bugtraq_id(60536);
  script_osvdb_id(94423);

  script_name(english:"IBM Notes 8.5 < 8.5.3 IF4 HF2 / 9.0 < 9.0 IF2 Password Disclosure");
  script_summary(english:"Checks version of IBM Notes");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Lotus Notes 8.5.x earlier than 8.5.3
Fix Pack 4 Interim Fix 2 or 9.0 earlier than Interim Fix 2. As such,
it is potentially affected by an information disclosure vulnerability.
IBM Notes may fail to zero the plaintext password within memory,
leaving the plaintext password accessible to an attacker with the
ability to access memory on the user's local workstation.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Notes 8.5.3 FP4 Interim Fix 2 / 9.0 Interim Fix 2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/security_bulletin_ibm_notes_may_fail_to_zero_the_plaintext_password_within_memory_cve_2013_05341?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c54826c2");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21636154");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_notes_installed.nasl");
  script_require_keys("SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

appname = 'IBM Lotus Notes';
kb_base = 'SMB/Lotus_Notes/';

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');
ver_ui = get_kb_item_or_exit(kb_base + 'Version_UI');

name   = kb_smb_name();
port   = kb_smb_transport();

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

# Try to connect to the server

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
share = hotfix_path2share(path:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

vuln = FALSE;
fixver = '';
if (version =~ '^8\\.5\\.' && ver_compare(ver:version, fix:'8.5.34.13086') < 0)
{
  vuln = TRUE;
  fixver = '8.5.34.13086';
}
else if (version =~ '^9\\.' && ver_compare(ver:version, fix:'9.0.0.13067') < 0)
{
  vuln = TRUE;
  fixver = '9.0.0.13067';
}

fixtimestamp = '';
if (!vuln)
{
  # If the version is FP4 or 9.0, we have to check the timestamp
  if (version == '8.5.34.13086' || version == '9.0.0.13067')
  {
    exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\notes.exe", string:path);
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
    {
     NetUseDel();
      exit(1, 'Failed to get the timestamp of ' + path + "\notes.exe");
    }
    if (version =~ '^8\\.' && int(timestamp) < 1364459259)
    {
      fixtimestamp = '1364459259';
      vuln = TRUE;
    }
    else if (version =~ '^9\\.' && int(timestamp) < 1362817062)
    {
      fixtimestamp = '1362817062';
      vuln = TRUE;
    }
  }
}
NetUseDel();

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version;
    if (fixtimestamp)
    {
      report +=
        '\n  File              : ' + path + "\notes.exe" +
        '\n  File Timestamp    : ' + timestamp +
        '\n  Fixed Timestamp   : ' + fixtimestamp + '\n';
    }
    else
    {
      report +=
        '\n  Fixed version     : ' + fixver + '\n';
    }
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, ver_ui, path);
