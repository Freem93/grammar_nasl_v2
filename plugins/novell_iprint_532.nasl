#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43060);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2009-1568","CVE-2009-1569");
  script_bugtraq_id(37242);
  script_osvdb_id(60803, 60804);
  script_xref(name:"Secunia", value:"35004");
  script_xref(name:"Secunia", value:"37169");

  script_name(english:"Novell iPrint Client < 5.32 Multiple Overflows");
  script_summary(english:"Checks version of Novell iPrint Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host has Novell iPrint Client installed.

The installed version of Novell iPrint Client is affected by multiple
buffer overflow vulnerabilities :

  - A stack-based buffer overflow exists due to insufficient
    boundary checks on the 'target-frame' parameter.
    (CVE-2009-1568)

  - A stack-based buffer overflow exists due to insufficient
    validation of time information. (CVE-2009-1569)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-40");
  script_set_attribute(
    attribute:"see_also",
    value:"http://secunia.com/secunia_research/2009-44"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2009/Dec/174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/fulldisclosure/2009/Dec/175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.novell.com/Download?buildid=29T3EFRky18~"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell iPrint Client 5.32 or later.

Note: There is no fix available for Novell iPrint Client 4.x branch.
Users should consider upgrading to 5.32");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell iPrint Client ActiveX Control Date/Time Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:iprint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1,"The 'SMB/Registry/Enumerated' KB item is not set to TRUE.");

winroot = hotfix_get_systemroot();
if (!winroot) exit(1, "The 'SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot' KB item is missing.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\nipplib.dll", string:winroot);

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(file:dll,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "The file '"+winroot+"\System32\nipplib.dll' does not exist.");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  version_ui = ver[0] + "." + ver[1] + ver[2];

  # Save the info for other plugins.
  set_kb_item(name:"SMB/Novell/iPrint/DLL", value:winroot + "\System32\nipplib.dll");
  set_kb_item(name:"SMB/Novell/iPrint/Version", value:join(ver, sep:"."));
  set_kb_item(name:"SMB/Novell/iPrint/Version_UI", value:version_ui);

  # Version that is not vulnerable.
  fixed_version_ui = "5.32";
  fix = split("5.3.2.0", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0)
      {
        report =
           '\n' +
          "File              : " + winroot + "\System32\nipplib.dll" + '\n' +
          "Installed version : " + version_ui +  '\n' +
          "Fixed version     : " + fixed_version_ui + '\n';
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      exit(0);
    }
    else if (ver[i] > fix[i])
      break;

 exit(0, "The host is not affected since Novell iPrint Client "+version_ui+" is installed.");
}
else exit(1, "Can't get file version of 'nipplib.dll'.");
