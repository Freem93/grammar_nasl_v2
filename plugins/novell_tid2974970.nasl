#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23978);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-0108");
  script_bugtraq_id(21886);
  script_osvdb_id(31358);

  script_name(english:"Novell Client TS/Citrix Session Arbitrary User Profile Invocation");
  script_summary(english:"Checks file version of nwgina.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a DLL that is affected by an
unauthorized access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file 'nwgina.dll' included with the Novell Client software
reportedly fails to delete user profiles when in a Terminal Server /
Citrix session. A local user may be able to leverage this issue to
invoke other user profiles on the affected host.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/docs/Readmes/InfoDocument/2974970.html");
  script_set_attribute(attribute:"solution", value:
"Install the 491psp3_nwgina.exe patch file referenced in the vendor
advisory above.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Unless we're being paranoid, check whether the software's installed.
if (report_paranoia < 2)
{
  subkey = "{Novell Client for Windows}";
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  get_kb_item_or_exit(key);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Check the version of nwgina.dll.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\nwgina.dll", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
info = "";
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # nb: for older versions, the file version will be null.
  if (isnull(ver)) info = "  " + winroot + "\System32\nwgina.dll (unknown file version" + ')\n';
  else
  {
    fix = split("4.91.1.38", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        info += "  " + winroot + "\System32\nwgina.dll (file version=" + version + ')\n';
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
NetUseDel();


# Issue a report if any vulnerable files were found.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "The following file is affected :\n",
      "\n",
      info
    );
  }
  else report = NULL;
  security_warning(port:port, extra:report);
}
