#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40799);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/11/11 19:58:27 $");

  script_cve_id("CVE-2007-5020");
  script_bugtraq_id(25748);
  script_osvdb_id(38068);

  script_name(english:"Adobe Acrobat < 8.1.1 Crafted PDF File Arbitrary Code Execution");
  script_summary(english:"Checks version of Adobe Acrobat");

  script_set_attribute(attribute:"synopsis", value:
"The version of Adobe Acrobat on the remote Windows host allows
execution of arbitrary code.");

  script_set_attribute(attribute:"description", value:
"The version of Adobe Acrobat installed on the remote host is earlier
than 8.1.1. Such versions allow execution of arbitrary code by means
of a specially crafted PDF file with a malicious 'mailto:' link.

Note that the issue only exists on systems running Windows XP or
Windows 2003 with Internet Explorer 7.0.");

  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb07-18.html");

  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Acrobat 8.1.1 or later or disable 'mailto' support as
described in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:acrobat");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("adobe_acrobat_installed.nasl", "smb_hotfixes.nasl", "smb_nativelanman.nasl");
  script_require_keys("SMB/Acrobat/Version", "Host/OS/smb", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");

# Only XP and 2003 are affected.
os = get_kb_item("Host/OS/smb");
if (!os) exit(1, "The 'Host/OS/smb' KB item is missing.");

if ("Windows 5.1" >!< os || "Windows 5.2" >!< os)
  exit( 0, "Only Windows XP and Windows 2003 are vulnerable." );

ie = hotfix_check_ie_version();
if (isnull(ie) || !ereg(pattern:"^7\.", string:ie))
  exit( 0, "Only installations of IE 7 are vulnerable." );

version = get_kb_item("SMB/Acrobat/Version");
if (isnull(version)) exit(1, "The 'SMB/Acrobat/Version' KB item is missing.");

if (version =~ "^(7\.0\.|8\.(0\.|1\.0))")
{
  # If we're paranoid, don't bother checking for the workaround.
  if (report_paranoia > 1)
  {
    report = string(
      "Note that Nessus did not check whether 'mailto' support was disabled\n",
      "for Adobe Acrobat because of the Report Paranoia setting in effect when\n",
      "this scan was run.\n"
    );
  }
  # Otherwise, look in the registry for the workaround.
  else
  {
    if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

    # Connect to the appropriate share.
    name    =  kb_smb_name();
    port    =  kb_smb_transport();
    #if (!get_port_state(port)) exit(0);
    login   =  kb_smb_login();
    pass    =  kb_smb_password();
    domain  =  kb_smb_domain();

    #soc = open_sock_tcp(port);
    #if (!soc) exit( 1, 'Failed to open socket' );

    #session_init(socket:soc, hostname:name);
    if(!smb_session_init()) exit(0);

    rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      exit( 1, "Can't connect to IPC$ share." );
    }

    # Connect to remote registry.
    hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(hklm))
    {
      NetUseDel();
      exit( 1, "Can't connect to the remote registry." );
    }

    # Get the launch permissions.
    perms = NULL;

    key = "SOFTWARE\Adobe\Acrobat Acrobat\7.0\FeatureLockDown\cDefaultLaunchURLPerms";
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
    if (isnull(perms) || "|mailto:3|" >!< perms)
    {
      report = string(
        "Nessus determined that Adobe's 'mailto' support has not been disabled in\n",
        "the registry.\n"
      );
    }
    else
      exit( 0, 'The workaround of disabling \'mailto\' support is in place.' );
  }

  version_ui = get_kb_item("SMB/Acrobat/Version_UI");
  if (report_verbosity > 0 && version_ui)
  {
    path = get_kb_item("SMB/Acrobat/Path");
    if (isnull(path)) path = "n/a";

    report = string(
      "\n",
      "  Path              : ", path, "\n",
      "  Installed version : ", version_ui, "\n",
      "  Fix               : 8.1.2 / 7.1.0\n",
      "\n",
      report
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "Acrobat "+version+" is not affected.");
