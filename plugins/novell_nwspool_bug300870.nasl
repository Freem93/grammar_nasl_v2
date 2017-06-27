#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25952);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-2954");
  script_bugtraq_id(25474);
  script_osvdb_id(37321);

  script_name(english:"Novell Client nwspool.dll RPC Printer Functions Remote Overflow (300870)");
  script_summary(english:"Checks file version of nwspool.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a DLL that is affected by multiple
buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The file 'nwspool.dll' included with the Novell Client software on the
remote host reportedly contains several buffer overflow
vulnerabilities that can be triggered via specially crafted RPC
requests. An unauthenticated, remote attacker may be able to leverage
these issues with overly long arguments to RPC requests such as
'RpcAddPrinterDriver' and 'RpcGetPrinterDriverDirectory' to cause a
denial of service or to execute arbitrary code remotely on the
affected host.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2007-57/advisory/");
  script_set_attribute(attribute:"see_also", value:"http://download.novell.com/Download?buildid=VOXNZb-6t_g~" );
  script_set_attribute(attribute:"solution", value:
"Install the 491psp2_3_4_nwspool.zip Field Test File per the vendor
advisory referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/30");

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

#

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

# Check the version of nwspool.dll.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\nwspool.dll", string:winroot);

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
  if (isnull(ver)) info = "  " + winroot + "\System32\nwspool.dll (unknown file version" + ')\n';
  else
  {
    fix = split("4.91.5.0", sep:'.', keep:FALSE);
    for (i=0; i<max_index(fix); i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        info += "  " + winroot + "\System32\nwspool.dll (file version=" + version + ')\n';
        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
NetUseDel();


# Issue a report if a vulnerable version of the file was found.
if (info)
{
  report = string(
    "The following file(s) are affected :\n",
    "\n",
    info
  );
  security_hole(port:port, extra:report);
}
