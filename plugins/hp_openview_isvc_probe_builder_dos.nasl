#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33771);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_cve_id("CVE-2008-1667");
  script_bugtraq_id(30403);
  script_osvdb_id(47515);

  script_name(english:"HP OVIS Probe Builder Service (PBOVISServer.exe) Arbitrary Remote Process Termination");
  script_summary(english:"Checks version of PBOVISServer.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that can be used to
terminate arbitrary processes.");
 script_set_attribute(attribute:"description", value:
"HP OpenView Internet Services (OVIS) is installed on the remote host.
It provides a single, integrated view of an organization's Internet
infrastructure.

The Probe Builder component included with the installation of HP OVIS
on the remote host allows an unauthenticated, remote attacker to
terminate any process on that host by sending a specially crafted
request packet to the Probe Builder Service, which listens by default
on TCP port 32968. The attacker must supply a valid process ID, but
can brute-force the ID and kill critical system processes, thereby
causing the system to crash.");
 # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=728
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2d66c58c");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494855" );
 # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01511225
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1c57ffd" );
 script_set_attribute(attribute:"solution", value:
"Apply the patch referenced in HP's advisory above and ensure the file
version of PBOVISServer.exe is 1.2.20.901.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(189);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/07/28");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:openview_internet_services");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Make sure the Probe Builder service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (!services || "PBOVISMessagingService" >!< services) exit(0);
}


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

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}

path = NULL ;

key   = "SOFTWARE\Hewlett-Packard\ProbeBuilder\CurrentVersion" ;
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If PBOVISServer is installed...
  item = RegQueryValue(handle:key_h, item:"AppDir");
  if (!isnull(item))
  {
    path = item[1];
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (!path)
{
 NetUseDel();
 exit(0);
}

NetUseDel(close:FALSE);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\bin\PBOVISServer.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
 NetUseDel();
 exit(0);
}

fh = CreateFile(file:exe,
	desired_access:GENERIC_READ,
	file_attributes:FILE_ATTRIBUTE_NORMAL,
	share_mode:FILE_SHARE_READ,
	create_disposition:OPEN_EXISTING);

ver = NULL;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}

NetUseDel();

# Check the version number.
if (!isnull(ver))
{
  # Version that is not vulnerable.
  fix = split("1.2.20.901", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      if (report_verbosity)
      {
        version = string(ver[0], ".", ver[1], ".", ver[2], ".",ver[3]);
        report = string(
          "\n",
	  "Version ", version, " of PBOVISServer.exe is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        if (report_paranoia < 2)
        {
          report = string(
            report,
            "\n",
            "Note, though, that Nessus did not check if the Probe Builder service\n",
            "was currently running because of the Report Paranoia setting in effect\n",
            "when this scan was run.\n"
          );
        }
        else
        {
          report = string(
            report,
            "\n",
            "In addition, Nessus has determined that the Probe Builder service is\n",
            "currently running.\n"
          );
        }
        security_hole(port:port, extra:report);
      }
      else security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}
