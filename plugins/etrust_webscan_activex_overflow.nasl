#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22160);
  script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");

  script_cve_id("CVE-2006-3976", "CVE-2006-3977");
  script_bugtraq_id(19399, 19403);
  script_osvdb_id(27785, 27786);

  script_name(english:"CA eTrust Antivirus WebScan ActiveX Control Vulnerabilities");
  script_summary(english:"Checks for version of WebScan ActiveX control");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The Windows remote host contains the WebScan ActiveX control, which is
used by Computer Associates' eTrust Antivirus WebScan service.

The version of this ActiveX control on the remote host reportedly
contains a buffer overflow and fails to properly validate parameters.
Exploitation of these issues may allow an unauthenticated, remote
attacker to execute arbitrary code or gain privileged access.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/442476/30/0/threaded");
 script_set_attribute(attribute:"see_also", value:"http://www.tippingpoint.com/security/advisories/TSRT-06-05.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Aug/188" );
 script_set_attribute(attribute:"see_also", value:"http://www3.ca.com/securityadvisor/vulninfo/vuln.aspx?id=34509" );
 script_set_attribute(attribute:"solution", value:
"Either remote the control or upgrade to WebScan v1.1.0.1048 or later
by visiting http://www3.ca.com/securityadvisor/virusinfo/scan.aspx and
allowing Internet Explorer to update a new version of webscan.cab.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/04");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

# Connect to the appropriate share.
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


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
clid = "7B297BFD-85E4-4092-B2AF-16A91B2EA103";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
file = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}


# If it is...
if (file)
{
  # Determine the version from the DLL itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file:dll,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # Check the version number.
  if (
    !isnull(ver) &&
    (
      ver[0] < 1 ||
      (
        ver[0] == 1 &&
        (
          ver[1] < 1 ||
          (
            ver[1] == 1 &&
            (ver[2] == 0 && ver[3] < 1048)
          )
        )
      )
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

    report = string(
      "\n",
      "Version ", version, " of the control is installed as \n",
      "\n",
      "  ", file, "\n"
    );
    security_hole(port:port, extra:report);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();
