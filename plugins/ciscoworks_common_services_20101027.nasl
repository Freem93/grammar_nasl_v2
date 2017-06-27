#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69469);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2010-3036");
  script_bugtraq_id(44468);
  script_osvdb_id(68927);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti41352");
  script_xref(name:"IAVA", value:"2010-A-0164");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20101027-cs");

  script_name(english:"CiscoWorks Common Services Arbitrary Code Execution (cisco-sa-20101027-cs)");
  script_summary(english:"Checks timestamp of mod_authz_host.so");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by an arbitrary code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of CiscoWorks Common Services installed on the remote
Windows host is potentially affected by multiple buffer overflows in
the Cisco developed authentication code of the web server module. By
exploiting these flaws, a remote, unauthenticated attacker could
execute arbitrary code subject to the privileges of the user running
the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/csa/cisco-sa-20101027-cs.html");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch from the advisory or upgrade to CiscoWorks
Common Services 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:ciscoworks_common_services");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("ciscoworks_common_services_installed.nasl");
  script_require_keys("SMB/CiscoWorks Common Services/Path", "SMB/CiscoWorks Common Services/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");

appname = 'CiscoWorks Common Services';
kb_base = 'SMB/CiscoWorks Common Services/';

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

ver = split(version, sep:'.', keep:FALSE);
for (i = 0; i < max_index(ver); i++)
  ver[i] = int(ver[i]);

if (ver[0] >= 4 || ver[0] < 3 || (ver[0] == 3 && ver[1] == 0 && ver[2] < 5))
  audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);

name   = kb_smb_name();
port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();



# Try to connect to the server

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

so = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\MDC\Apache\modules\mod_authz_host.so", string:path);
share = hotfix_path2share(path:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fixtimestamp = '';
if (ver[0] == 3)
{
  fh = CreateFile(
    file:so,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (isnull(fh))
  {
    NetUseDel();
    audit(AUDIT_VER_FAIL, (share - '$') + ':' + so);
  }

  ret = GetFileVersionEx(handle:fh);
  CloseFile(handle:fh);

  if (!isnull(ret))
    timestamp = ret['dwTimeDateStamp'];

  if (isnull(timestamp))
  {
    NetUseDel();
    exit(1, 'Failed to get the timestamp of ' + (share - '$') + ':' + so);
  }

  if (ver[1] < 3)
  {
    if (int(timestamp) < 1282073580)
      fixtimestamp = '1282073580';
  }
  else if (ver[1] == 3)
  {
    if (int(timestamp) < 1286288040)
      fixtimestamp = '1286288040';
  }
}
NetUseDel();

if (fixtimestamp)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  File              : ' + (share - '$') + ':' + so +
      '\n  File Timestamp    : ' + timestamp +
      '\n  Fixed Timestamp   : ' + fixtimestamp + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, appname, version, path);
