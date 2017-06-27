#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(57796);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/03 20:40:06 $");

  script_cve_id(
    "CVE-2011-3478",
    "CVE-2011-3479",
    "CVE-2012-0290",
    "CVE-2012-0291"
  );
  script_bugtraq_id(51592, 51593, 51862, 51965);
  script_osvdb_id(78532, 78533, 78988, 79601);
  script_xref(name:"EDB-ID", value:"18493");
  script_xref(name:"IAVA", value:"2012-A-0019");
  script_xref(name:"EDB-ID", value:"18823");
  script_xref(name:"EDB-ID", value:"19407");

  script_name(english:"Symantec pcAnywhere Multiple Vulnerabilities (SYM12-002)");
  script_summary(english:"Checks version of awhlogon.dll");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
remote vulnerabilities.");

  script_set_attribute(attribute:"description", value:
"The version of Symantec pcAnywhere installed on the remote host is
potentially affected by multiple vulnerabilities :

  - When handling an authentication request the process
    copies the user-supplied username unsafely to a
    fixed-length buffer, which could lead to arbitrary code
    execution. (CVE-2011-3478)

  - A local privilege escalation vulnerability exists
    because some files uploaded to the system during
    product installation are installed as writable by
    everyone. (CVE-2011-3479)

  - During a valid client server session unexpected input to
    the client can result in an exception error.  This can
    create an acess violation resulting in the remote
    session being dropped but leaving the client session
    open in specific instances. (CVE-2012-0290)

  - Malformed input to a client or server or, an unexpected
    response to a request could potentially destabilize the
    application causing it to hang or crash resulting in a
    denial of service. (CVE-2012-0291)");

  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-018/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jan/154");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jan/155");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Jan/161");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Apr/230");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Apr/231");
   # http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120124_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6968fc0");
  script_set_attribute(attribute:"solution", value:"Apply the hotfix referenced in the Symantec advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:pcanywhere");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_pcanywhere_installed.nasl");
  script_require_keys("SMB/Symantec pcAnywhere/Path", "SMB/Symantec pcAnywhere/Version");
  script_require_ports(139, 445);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('smb_func.inc');
include('audit.inc');

path = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Path');
version = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Version');
build = get_kb_item_or_exit('SMB/Symantec pcAnywhere/Build');

ver = split(version, sep:'.');
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# The hotfix is only available for version 12.x
if (ver[0] == 12)
{
  # Connect to the appropriate share
  name   = kb_smb_name();
  port   = kb_smb_transport();
  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();



  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:'\\1$', string:path);
  dll   = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\awhlogon.dll', string:path);

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, 'Can\'t connect to '+share+' share.');
  }

  # Check the version of awhlogon.dll
  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    NetUseDel();
    exit(1, 'Couldn\'t open \''+(share-'$')+':'+dll+'\'.');
  }

  dllver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
  NetUseDel();

  if (isnull(dllver)) exit(1, 'Couldn\'t get the version \''+(share-'$')+':'+dll+'\'.');
  for (i=0; i<max_index(dllver); i++)
    dllver[i] = int(dllver[i]);

  dllversion = join(dllver, sep:'.');
  fix = NULL;
  if (ver[1] == 5)
  {
    if (ver[2] == 1 && build == 486)
      fix = '12.5.1.500';
    else if (ver[2] == 0 && (build == 463 || build == 442))
      fix = '12.5.0.480';
    else if (ver[2] == 0 && build == 265)
      fix = '12.5.0.300';
  }
  else if (ver[1] == 1)
  {
    if (ver[2] == 0 && (build == 469 || build == 464))
      fix = '12.1.0.470';
    else if (ver[2] == 0 && build == 448)
      fix = '12.1.0.450';
  }
  else if (ver[1] == 0)
  {
    if (ver[2] == 3 && build == 202)
      fix = '12.0.3.210';
    else if (ver[2] == 2 && build == 166)
      fix = '12.0.2.366';
    else if (ver[2] == 1 && build == 156)
      fix = '12.0.1.357';
  }
  if (fix)
  {
    if (ver_compare(ver:dllversion, fix:fix) == -1)
    {
      if (report_verbosity > 0)
      {
        report =
          '\n  Path              : ' + path +
          '\n  Affected DLL      : ' + dll +
          '\n  Installed version : ' + join(dllver, sep:'.') +
          '\n  Fixed version     : ' + fix + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else exit(0, 'awhlogon.dll version '+join(dllver, sep:'.')+' was detected on the remote host, and thus is not affected.');
  }
}
