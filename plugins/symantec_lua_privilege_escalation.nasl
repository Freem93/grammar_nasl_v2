#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59193);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/06 17:22:01 $");

  script_cve_id("CVE-2012-0304");
  script_bugtraq_id(53903);
  script_osvdb_id(81902);
  script_xref(name:"TRA", value:"TRA-2012-04");

  script_name(english:"Symantec LiveUpdate Administrator Insecure Permissions Local Privilege Escalation (credentialed check)");
  script_summary(english:"Checks permissions of LUA install directory");

  script_set_attribute(attribute:"synopsis", value:
"An update management application installed on the remote Windows host
has a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec LiveUpdate Administrator (LUA) installed on
the remote host has a privilege escalation vulnerability. The
installation directory allows write access to the Everyone group. This
directory contains batch files that are periodically executed as
SYSTEM. A local, unprivileged attacker could exploit this by creating
or modifying files that will be executed as SYSTEM, resulting in
privilege escalation.

A partial fix for this issue was included in LUA 2.3.1, but it does
not mitigate all possible attack vectors.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-04");
  # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120615_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f93f8d81");
  script_set_attribute(attribute:"solution", value:"Upgrade to Symantec LiveUpdate Administrator 2.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:liveupdate_administrator");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_lua_installed.nasl");
  script_require_keys("SMB/symantec_lua/path");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

# these should probably be put into an include file
ACCESS_ALLOWED_ACE_TYPE = 0;
ACCESS_DENIED_ACE_TYPE = 1;

##
# Gets the DACL of the given file
#
# @anonparam fh handle of the file to obtain the DACL for
#
# @return DACL associated with 'fh'
##
function get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);
  if (isnull(sd))
    return NULL;

  dacl = sd[3];
  if (isnull(dacl))
    return NULL;

  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
    return NULL;

  return dacl;
}

path = get_kb_item_or_exit("SMB/symantec_lua/path");

match = eregmatch(string:path, pattern:"^([A-Za-z]):(.+)$");
if (isnull(match))
{
  exit(1, 'Unable to parse path: ' + path);
}

share = match[1] + '$';
dir = match[2];

name    =  kb_smb_name();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();
port    =  kb_smb_transport();


if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);

if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

fh = CreateFile(
  file:dir,
  desired_access:STANDARD_RIGHTS_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

vuln = FALSE;

if (!isnull(fh))
{
  dacl = get_dacl(fh);
  CloseFile(handle:fh);

  foreach ace (dacl)
  {
    ace = parse_dacl(blob:ace);
    if (isnull(ace))
      continue;

    rights = ace[0];
    type = ace[3];
    sid = sid2string(sid:ace[1]);
    if (isnull(sid))
      continue;

    # from http://msdn.microsoft.com/en-us/magazine/cc982153.aspx
    #   The system parses ACEs in order, from first to last, until access is either granted or denied.
    #   Thus, ordering of ACEs is important.  "Deny permissions" should be placed before "allow permissions."
    # so we'll stop on the first match for Everyone (1-1-0) involving the file write/creation permission
    if (sid == '1-1-0' && rights & FILE_WRITE_DATA)
    {
      if (type == ACCESS_ALLOWED_ACE_TYPE)
        vuln = TRUE;
      break;
    }
  }
}

NetUseDel();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');

if (report_verbosity > 0)
{
  report =
    '\nThe following directory allows write access for the Everyone group :\n\n' +
    path + '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
