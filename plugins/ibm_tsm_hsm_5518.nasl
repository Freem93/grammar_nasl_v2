#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35906);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/16 14:02:51 $");

  script_cve_id("CVE-2009-0869");
  script_bugtraq_id(34034);
  script_osvdb_id(52530);

  script_name(english:"IBM Tivoli Storage Manager HSM Client < 5.5.1.8 / 5.4.2.6");
  script_summary(english:"Checks the version number of IBM Tivoli Storage Manager HSM Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a backup client that is affected by a
remote buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of IBM Tivoli Storage Manager HSM
Client that is earlier than 5.4.2.6 / 5.5.1.8. Such versions are
reportedly affected by a remote buffer overflow vulnerability. An
attacker could exploit this to run arbitrary code with the permissions
of the affected application.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21329223");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Tivoli Storage Manager HSM Client version 5.4.2.6 /
5.5.1.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_storage_manager_hsm");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");

name      = kb_smb_name();
port      = kb_smb_transport();

login     = kb_smb_login();
pass      = kb_smb_password();
domain    = kb_smb_domain();



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

path = NULL;

installstring="SOFTWARE\IBM\ADSM\CurrentVersion\HSMClient";
key_h = RegOpenKey(handle:hklm, key:installstring, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item)) path = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);

if (isnull(path))
{
  NetUseDel();
  exit(0);
}
NetUseDel(close:FALSE);


# Determine the version from hsmservice.exe
ver = NULL;

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\hsmservice.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if(rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
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

# Clean up.
NetUseDel();

# Determine if the version is vulnerable
if (ver)
{
  for(i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (
    ver[0]==5 &&
    (
      (
        ver[1]==3 && ver[2]>=2 &&
        (
          ver[3]<5 ||
          (
            ver[3]==5 && ver[4]==0
          )
        )
      ) ||
      (
        ver[1]==4 &&
        (
          ver[2] < 2 ||
          (
            ver[2]==2 && ver[3]<=5
          )
        )
      ) ||
      (
        ver[1]==5 &&
        (
          ver[2]<1 ||
          (
            ver[2]==1 && ver[3]<=4
          )
        )
      )
    )
  )
  {
    if (report_verbosity > 0)
    {
      version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);

      report = string(
        "\n",
        "Nessus has identified the following vulnerable instance of\n",
        "IBM Tivoli Storage Manager HSM Client on the remote host :\n",
        "\n",
        "Path    : ", path, "\n",
        "Version : ", version, "\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
  }
}
