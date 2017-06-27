#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33481);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2008-3158");
  script_bugtraq_id(30001);
  script_osvdb_id(46578);
  script_xref(name:"Secunia", value:"30904");

  script_name(english:"Novell Client nwfs.sys Local Privilege Escalation");
  script_summary(english:"Checks file version of nwfs.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a driver that is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file 'NWFS.SYS' included with the Novell Client software and
installed on the remote host is reportedly affected by a local
privilege escalation vulnerability that allows a client to send a
request to the kernel driver using crafted pointer and then execute
code with kernel privileges.");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5028543.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4de64f2");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell Client 4.91 SP4 nwfs.sys Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
  subkey = "Novell Client for Windows";
  key = string("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/", subkey, "/DisplayName");
  get_kb_item_or_exit(key);
}


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


# Check the version of nwfs.sys.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\NetWare\nwfs.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:sys,
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

  # nb: for older versions, the file version may be null.
  if (isnull(ver)) info = "  " + winroot + "\System32\NetWare\nwfs.sys (unknown file version" + ')\n';
  else
  {
    fix = split("4.91.4.12", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        info += "  " + winroot + "\System32\NetWare\nwfs.sys (file version=" + version + ')\n';
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
NetUseDel();


# Issue a report if a vulnerable file was found.
if (info)
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The following file is affected :\n",
      "\n",
      info
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
