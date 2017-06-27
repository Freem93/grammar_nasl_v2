#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23979);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/16 22:04:05 $");

  script_cve_id("CVE-2006-5545");
  script_bugtraq_id(19866);
  script_osvdb_id(29895);

  script_name(english:"Symantec Mail Security for Domino Arbitrary Mail Relay");
  script_summary(english:"Checks file version of smsdkick.exe"); 
 
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that allows
unauthorized mail relaying.");
  script_set_attribute(attribute:"description", value:
"Symantec Mail Security for Domino, which provides antispam and anti-
virus protection for Lotus Domino, is installed on the remote Windows
host. 

The Premium Antispam feature included with the version of Symantec
Mail Security for Domino on the remote host reportedly fails to
recognize and reject a specific SMTP recipient address format.  A
remote attacker may be able to leverage this flaw to relay spam and
other types of messages through the remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2006.10.19.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Mail Security for Domino version 5.1.2.28 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/19");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the Premium Antispam service is running, unless we're 
# being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (
    !services ||
    ("BMICONDUITSVC" >!< services && "Symantec Premium AntiSpam Conduit" >!< services)
  ) exit(0);
}



# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
if (!get_port_state(port)) exit(0);
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

soc = open_sock_tcp(port);
if (!soc) exit(0);

session_init(socket:soc, hostname:name);
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


# Find where it's installed.
paths = make_list();
key = "SOFTWARE\\Symantec\\Symantec Mail Security for Domino";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  info = RegQueryInfoKey(handle:key_h);
  for (i=0; i<info[1]; ++i) {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (strlen(subkey) && subkey =~ "^[0-9.]+$")
    {
      key2 = string(key, "\\Install\\", subkey);
      key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);
      if (!isnull(key2_h))
      {
        value = RegQueryValue(handle:key2_h, item:"InstallDir");
        if (!isnull(value)) paths = make_list(paths, value[1]);

        RegCloseKey(handle:key2_h);
      }
    }
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# Check the version of each install.
foreach path (paths)
{
  NetUseDel(close:FALSE);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\PAS\Bin\smsdkick.exe", string:path);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
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

    # nb: for older versions, the file version will be null.
    if (isnull(ver)) info = "  " + path + "\PAS\Bin\smsdkick.exe (unknown file version" + ')\n';
    else
    {
      fix = split("5.1.0.28", sep:'.', keep:FALSE);
      for (i=0; i<4; i++)
        fix[i] = int(fix[i]);

      for (i=0; i<max_index(ver); i++)
        if ((ver[i] < fix[i]))
        {
          version = string(ver[0], ".", ver[1], ".", ver[2], ".", ver[3]);
          info = 'Nessus determined that Symantec Mail Security for Domino version\n' +
            version + ' is installed on the remote host.\n';
          if (report_paranoia > 1)
            info += '\n' +
              'Note that Nessus did not actually check whether the Premium\n' +
              'Antispam service was running because report paranoia was set\n' +
              "to 'paranoid'." + '\n';

          security_warning(port:port, extra: info);
          break;
        }
        else if (ver[i] > fix[i])
          break;
    }
  }
}


# Clean up.
NetUseDel();
