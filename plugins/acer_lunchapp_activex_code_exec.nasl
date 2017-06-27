#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(24012);
  script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/01/12 17:12:42 $");

  script_cve_id("CVE-2006-6121");
  script_bugtraq_id(21207);
  script_osvdb_id(30513);

  script_name(english:"Acer LunchApp.APlunch ActiveX Arbitrary Command Execution");
  script_summary(english:"Checks for Acer LunchApp.APlunch ActiveX control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that allows arbitrary
code execution.");
  script_set_attribute(attribute:"description", value:
"The remote host contains an ActiveX control from Acer called
LunchApp.APlunch that is reportedly shipped with notebook computers
from that manufacturer and is marked as 'safe for scripting' and 'safe
for initializing from persistent data'. By tricking a user on the
affected host into visiting a specially crafted web page, an attacker
can pass arbitrary commands to the 'Run' method that will be executed
on the remote host subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://vuln.sg/acerlunchapp-en.html");
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.acer-euro.com/drivers/utilities.html#APP"
  );
  script_set_attribute(attribute:"solution", value:"Run the security patch referenced in the vendor advisory above.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/12");

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


include("smb_func.inc");


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

if (!smb_session_init()) exit(0);


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


# Determine if the control is installed.
clid = "D9998BD0-7957-11D2-8FED-00606730D3AA";
key = "SOFTWARE\Classes\CLSID\{" + clid +  "}\InprocServer32";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
file = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value)) file = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (file)
{
  # Determine the version from the DLL itself.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  ocx =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  # Make sure the control exists.
  fh = CreateFile(
    file:ocx,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    CloseFile(handle:fh);
    report = string(
      "\n",
      "Acer's LunchApp.APlunch ActiveX control is installed as :\n",
      "\n",
      "  ", file, "\n"
    );
    security_hole(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
