#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(27584);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 19:58:28 $");

  script_cve_id("CVE-2007-5020");
  script_bugtraq_id(25748);
  script_osvdb_id(38068);

  script_name(english:"Adobe Reader < 8.1.1 Crafted PDF File Arbitrary Code Execution ");
  script_summary(english:"Checks version of Adobe Reader");

  script_set_attribute(attribute:"synopsis", value:
"The PDF file viewer on the remote Windows host allows execution of
arbitrary code.");
  script_set_attribute(attribute:"description", value:
"The installation of Adobe Reader on the remote host allows execution
of arbitrary code by means of a specially crafted PDF file with a
malicious 'mailto:' link.

Note that the issue only exists on systems running Windows XP or
Windows 2003 with Internet Explorer 7.0.");
  script_set_attribute(attribute:"see_also", value:"http://www.gnucitizen.org/blog/0day-pdf-pwns-windows");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/480080/100/0/threaded" );
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-18.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Reader 8.1.1 or later or disable 'mailto' support as
described in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/10/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_reader_installed.nasl", "smb_hotfixes.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/Acroread/Version", "Host/OS/smb", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

#

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

# Only XP and 2003 are affected.
os = get_kb_item("Host/OS/smb");
if (!os) exit(0, 'The "Host/OS/smb" KB item is missing.');

if ("Windows 5.1" >!< os && "Windows 5.2" >!< os)
  exit(0, 'The remote host does not appear to be Windows XP or 2003.');

# And it requires IE 7.
ie = hotfix_check_ie_version();
if (isnull(ie) || !ereg(pattern:"^7\.", string:ie))
  exit(0, 'The remote host does not appear to have IE 7 installed.');

port = kb_smb_transport();

# Check for the workaround (if not paranoid)
if (report_paranoia < 2)
{
  if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

  # Connect to the appropriate share.
  name    =  kb_smb_name();
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
    exit(0);
  }

  # Get the launch permissions.
  perms = NULL;

  key = "SOFTWARE\Adobe\Acrobat Reader\7.0\FeatureLockDown\cDefaultLaunchURLPerms";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"tSchemePerms");
    if (!isnull(value)) perms = value[1];
    RegCloseKey(handle:key_h);
  }
  RegCloseKey(handle:hklm);

  # Clean up.
  NetUseDel();

  # Check perms.
  if (!isnull(perms) && "|mailto:3|" >< perms)
    exit(0, "Adobe's 'mailto' support has been disabled in the registry, therefore the host is not affected.");
}

info = NULL;
vers = get_kb_list("SMB/Acroread/Version");
if (isnull(vers)) exit(0, 'The "SMB/Acroread/Version" KB item is missing.');

foreach ver (vers)
{
  if (ver && ver =~ "^(7\.0\.|8\.(0\.|1\.0))")
  {
    path = get_kb_item('SMB/Acroread/'+ver+'/Path');
    if (isnull(path)) exit(1, 'The "SMB/Acroread/'+ver+'/Path" KB item is missing.');

    verui = get_kb_item('SMB/Acroread/'+ver+'/Version_UI');
    if (isnull(verui)) exit(1, 'The "SMB/Acroread/'+ver+'/Version_UI" KB item is missing.');

    info += '  - ' + verui + ', under ' + path + '\n';
  }
}

if (isnull(info)) exit(0, 'The host is not affected.');

if (report_verbosity > 0)
{
  if (max_index(split(info)) > 1) s = "s of Adobe Reader are";
  else s = " of Adobe Reader is";

  report =
    '\nThe following vulnerable instance'+s+' installed on the'+
    '\nremote host :\n\n'+
    info;
  if (report_paranoia > 1)
  {
    report += '\nNote that Nessus did not check whether \'mailto\' support was disabled'+
              '\nfor Adobe Reader because of the Report Paranoia setting in effect when'+
              '\nthis scan was run.\n';
  }
  else
  {
    report += '\nNessus determined that Adobe\'s \'mailto\' support has not been disabled in'+
              '\nthe registry.\n';
  }

  security_hole(port:port, extra:report);
}
else security_hole(port);
