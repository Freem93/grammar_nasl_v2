#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33901);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/01/12 17:12:43 $");

  script_cve_id("CVE-2008-2926", "CVE-2008-3174");
  script_bugtraq_id(30651);
  script_osvdb_id(47593, 47594);

  script_name(english:"CA HIPS Kmxfw.sys Driver Multiple Remote Vulnerabilities");
  script_summary(english:"Checks version of Kmxfw.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a kernel driver that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The 'kmxfw.sys' kernel driver included with CA's Host-Based Intrusion
Prevention System (HIPS) or a related security product installed on
the remote host is affected by multiple vulnerabilities.

  - By sending specially crafted IOCTL requests, it may be
    possible for a local attacker to crash the system or
    execute arbitrary code with kernel level privileges.
    (CVE-2008-2926)

  - An unspecified flaw may allow a remote attacker to crash
    the system. (CVE-2008-3174)");
  script_set_attribute(attribute:"see_also", value:"http://www.trapkit.de/advisories/TKADV2008-006.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495397" );
  script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36559" );
  script_set_attribute(attribute:"see_also", value:"http://www.ca.com/us/securityadvisor/vulninfo/vuln.aspx?id=36560" );
  script_set_attribute(attribute:"solution", value:
"Follow the instructions on the CA HIPS implementation guide to update
the CA HIPS client, and ensure the 'kmxfw.sys' driver is version
6.5.5.18 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
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
  exit(0);
}
NetUseDel(close:FALSE);


# Grab the file version of the affected file.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\kmxfw.sys", string:winroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

version = NULL;
company = NULL;
pname = NULL;
if (!isnull(fh))
{
  ret = GetFileVersionEx(handle:fh);
  if (!isnull(ret)) children = ret['Children'];

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
        pname    = data['ProductName'];
      }
    }
  }
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (
  !isnull(version) &&
  (
    (!isnull(company) && "CA" >< company) ||
    (!isnull(pname) && "Host Intrusion Prevention System" >< pname)
  )
)
{
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("6.5.5.18", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Version ", version, " of the affected driver is installed as :\n",
          "\n",
          "  ", winroot, "\\System32\\drivers\\kmxfw.sys\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
