#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40907);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id("CVE-2009-0199", "CVE-2009-2628");
  script_bugtraq_id(36290);
  script_osvdb_id(57835, 57836);
  script_xref(name:"VMSA", value:"2009-0012");
  script_xref(name:"Secunia", value:"34938");

  script_name(english:"VMnc Media Codec Multiple Heap Overflows (VMSA-2009-0012)");
  script_summary(english:"Checks version of vmnc.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
heap overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"VMnc media codec is installed on the remote host. The codec is
typically installed along with VMware Workstation, VMware Player,
VMware ACE or in its standalone configuration by installing VMware
Workstation Movie Decoder and is required to play movies recorded with
VMware applications.

The installed version is affected by multiple heap-based buffer
overflow vulnerabilities. By tricking an user into opening a specially
crafted video file with incorrect framebuffer parameters, an attacker
may be able to exploit these vulnerabilities to trigger a denial of
service condition or execute arbitrary code on the remote system.");

  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2009-0012.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

 - VMware Workstation 6.5.3 or higher.
    - VMware Player 2.5.3 or higher.
    - VMware Movie Decoder 6.5.3 or higher (if used in
    standalone configuration).");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:ace");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:movie_decoder");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The 'SMB/Registry/Enumerated' KB item is missing.");

# Get the install path

name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1,"Can't connect to IPC$ share.");
}

winroot = hotfix_get_systemroot();
if (!winroot) exit(1,"Can't get winroot.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\vmnc.dll", string:winroot);

NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(1,"Can't connect to "+ share + " share with the supplied credentials.");
}

fh = CreateFile(file:dll,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

if (isnull(fh))
{
  NetUseDel();
  exit(0, "The file '"+winroot+"\System32\vmnc.dll' does not exist.");
}

version = NULL;
company = NULL;

ret = GetFileVersionEx(handle:fh);
if (!isnull(ret)) children = ret['Children'];
if (!isnull(children))
{
  stringfileinfo = children['StringFileInfo'];
  if (!isnull(stringfileinfo))
  {
    foreach key (keys(stringfileinfo))
    {
      data = stringfileinfo[key];
      if (!isnull(data))
      {
        version  = data['FileVersion'];
        company  = data['CompanyName'];
      }
    }
  }
}
CloseFile(handle:fh);
NetUseDel();

# Check if we are looking at a DLL from VMware, Inc.
if("VMware, Inc" >!< company)
  exit(1, "CompanyName '" + company + "' for vmnc.dll does not appear to be from VMware, Inc.");

# Extract the version number.
# e.g 6.5.3 build-185404
# Do not look for 'build' in regex as could it be language dependent.

if (!isnull(version) && ereg(pattern:"^[0-9]+\.[0-9]+\.[0-9]+ .+$",string:version))
  version = ereg_replace(pattern:"^([0-9]+\.[0-9]+\.[0-9]+) .+$",string:version,replace:"\1");
else
 version = NULL;

# Check the version number.
if (!isnull(version))
{
  # Version of the driver that is not vulnerable
  fix = split("6.5.3", sep:'.', keep:FALSE);
  for (i=0; i < max_index(fix); i++)
    fix[i] = int(fix[i]);

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  for (i=0; i < max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity > 0 )
      {
        report = string(
          "\n",
          "Version ", version, " of the affected codec is installed as :\n",
          "\n",
          "  ", winroot, "\\system32\\vmnc.dll\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
    {
      break;
      exit(0,"The installed version of the VMnc Media Codec is not affected.");
    }
}
