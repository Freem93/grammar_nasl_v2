#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25337);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-2845", "CVE-2007-2846");
  script_bugtraq_id(24132, 24155);
  script_osvdb_id(36522, 36523);

  script_name(english:"avast! CAB / SIS File Handling Buffer Overflow");
  script_summary(english:"Checks version of avast!");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is susceptible to
buffer overflow attacks.");
 script_set_attribute(attribute:"description", value:
"The remote host is running avast! Server Edition or Managed Client.

The version of the avast! product installed on the remote host is
reportedly prone to a heap-based overflow in its CAB and SIS file
processing code. An attacker may be able to exploit these issues to
execute arbitrary code on the remote host, likely with LOCAL SYSTEM
privileges.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/May/369" );
 # http://web.archive.org/web/20070516181540/http://www.avast.com/eng/avast-4-server-revision-history.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21384a15" );
 script_set_attribute(attribute:"see_also", value:"http://www.avast.com/eng/adnm-management-client-revision-history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to avast! Server Edition 4.7.766 / avast! Managed Client
4.7.700 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/16");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/25");

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

#

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
if (
  !isnull(path) && !isnull(prod) && !isnull(version) &&
  (prod == "av_srv" || prod == "av_net")
)
{
  # Check the version number.
  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  prod_name = "";
  if (prod == "av_srv")
  {
    prod_name = "avast! Server Edition";
    fix = split("4.7.766", sep:'.', keep:FALSE);
  }
  else if (prod == "av_net")
  {
    prod_name = "avast! Managed Client";
    fix = split("4.7.700", sep:'.', keep:FALSE);
  }

  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if (ver[i] < fix[i])
    {
      report = string(
        prod_name, " version ", version, " is installed under : \n",
        "\n",
        "  ", path, "\n"
      );
      security_hole(port:port, extra:report);

      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Clean up.
NetUseDel();
