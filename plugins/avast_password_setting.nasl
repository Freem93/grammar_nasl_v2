#
#  (C) Tenable Network Security
#


include("compat.inc");

if (description)
{
  script_id(24280);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2007-0829");
  script_bugtraq_id(22425);
  script_osvdb_id(33114);

  script_name(english:"avast! Antivirus Server Edition Password Setting Weakness");
  script_summary(english:"Checks version of avast Server Edition's aswEngin.dll");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is susceptible to
an authentication bypass issue.");
 script_set_attribute(attribute:"description", value:
"The remote host is running avast! Antivirus Server Edition.

The installed version of this software reportedly does not ask for a
password even if one is set. A local attacker may be able to leverage
this issue to bypass authentication and manipulate settings of the
affected application.");
 # http://web.archive.org/web/20070516181540/http://www.avast.com/eng/avast-4-server-revision-history.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21384a15");
 script_set_attribute(attribute:"solution", value:"Upgrade to avast! Antivirus Server Edition 4.7.726 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/06");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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


# Grab installation path and version from the registry.
path = NULL;
prod = NULL;
version = NULL;
key = "SOFTWARE\ALWIL Software\Avast\4.0";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Avast4ProgramFolder");
  if (!isnull(value)) path = value[1];

  value = RegQueryValue(handle:key_h, item:"Product");
  if (!isnull(value)) prod = value[1];

  value = RegQueryValue(handle:key_h, item:"VersionShort");
  if (!isnull(value)) version = value[1];

  value = RegQueryValue(handle:key_h, item:"SetupVersion");
  if (!isnull(value)) version += "." + value[1];

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);


# If it's installed...
if (!isnull(path) && !isnull(prod) && prod == "av_srv" && !isnull(version))
{
  # Check the version number.
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fix = split("4.7.726", sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      report = string(
        "avast! Anvitirus Server Edition version ", version, " is installed under : \n",
        "\n",
        "  ", path, "\n"
      );
      security_warning(port:port, extra:report);

      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
