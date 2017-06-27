#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33480);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2008-5121");
  script_bugtraq_id(29772);
  script_osvdb_id(46272);
  script_xref(name:"CERT", value:"858993");

  script_name(english:"Deterministic Network Extender 'dne2000.sys' Local Privilege Escalation");
  script_summary(english:"Checks for vulnerable version of dne2000.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a kernel driver that is affected by a local
privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"A kernel driver from Deterministic Network Extender (DNE) is installed
on the remote host. DNE is typically packaged with third-party
applications and is reportedly included with :

- SafeNet HighAssurance Remote and SoftRemote
    - Cisco VPN Client
    - Blue Coat Systems WinProxy

The installed version of 'dne2000.sys' is affected by a local
privilege escalation issue. By sending a specially crafted IOCTL
request, it may be possible to execute arbitrary code with kernel
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.securityfocus.com/vulnerabilities/exploits/29772.c");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d23102b" );
  script_set_attribute(attribute:"solution", value:"Upgrade to dne2000.sys version 3.21.12.17902");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

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

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);

name    =  kb_smb_name();
port    =  kb_smb_transport();
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
NetUseDel(close:FALSE);

# Get the share.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\dne2000.sys", string:winroot);

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
ver = NULL;

# Grab the file version of the affected file.
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  # According to US-CERT v3.21.12.17902 is the fixed version

  fix = split("3.21.12.17902", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
	version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
        report = string(
          "\n",
          "Version ", version, " of the affected kernel driver is installed as :\n",
          "\n",
          "  ", winroot, "\\System32\\drivers\\dne2000.sys\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
