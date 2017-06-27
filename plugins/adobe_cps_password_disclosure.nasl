#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22540);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/09/24 20:59:27 $");

  script_cve_id("CVE-2006-5199");
  script_bugtraq_id(20439);
  script_osvdb_id(29672);

  script_name(english:"Adobe Contribute Publishing Server Administrator Password Local Disclosure");
  script_summary(english:"Checks for administrator password in Adobe Contribute Publishing Server installation log");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"Adobe Contribute Publishing Server, a web publishing management
application, is installed on the remote Windows host.

The version of Contribute Publishing Server on the remote host logged
a copy of the password specified for the administrator as part of the
installation process. A local user may be able to leverage this flaw
to gain administrative access to the affected application and
potentially other resources.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb06-15.html");
  script_set_attribute(attribute:"solution", value:
"Change the application's administrator password and remove the
installation log as described in the vendor advisory referenced above.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:contribute");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "Settings/ParanoidReport");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

# Exit unless we're paranoid because we don't have a good way to validate
# the password we find.
if (report_paranoia < 2) audit(AUDIT_PARANOID);


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name = kb_smb_name();
port = kb_smb_transport();
#if (!get_port_state(port)) exit(0);
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.
#soc = open_sock_tcp(port);
#if (!soc) exit(0);
#session_init(socket:soc, hostname:name);

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');


rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(0);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Check whether it's installed.
key = "SOFTWARE\Macromedia\Macromedia Contribute Publishing Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
path = NULL;
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Installation_Dir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is, try to grab the admin password.
admin_pw = NULL;
if (!isnull(path))
{
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  file =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\UninstallerData\installvariables.properties", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(0);
  }

  fh = CreateFile(
    file               : file,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize > 10240) fsize = 10240;
    if (fsize)
    {
      data = ReadFile(handle:fh, length:fsize, offset:0);
      if (data && '\nCONFIRM_ADMIN_PASSWORD=' >< data)
      {
        admin_pw = strstr(data, '\nCONFIRM_ADMIN_PASSWORD=') - '\nCONFIRM_ADMIN_PASSWORD=';
        admin_pw = admin_pw - strstr(admin_pw, '\n');
        if (admin_pw) admin_pw = chomp(admin_pw);
      }
    }

    CloseFile(handle:fh);
  }
}


# There's a problem if we have a password.
if (admin_pw)
{
  if (report_verbosity)
    report = strcat(
      'Nessus was able to read the following password from the installation\n',
      'log but has not tried to validate it :\n',
      '\n',
      '  ', admin_pw
    );
  else report = NULL;

  security_note(port:kb_smb_transport(), extra:report);
}


# Clean up.
NetUseDel();
