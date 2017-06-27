#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55047);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/13 15:33:30 $");

  script_cve_id("CVE-2011-0548");
  script_bugtraq_id(48013);
  script_osvdb_id(72710);
  script_xref(name:"Secunia", value:"44779");
  script_xref(name:"CERT", value:"126159");

  script_name(english:"Symantec Mail Security KeyView PRZ Processing Buffer Overflow");
  script_summary(english:"Checks file version of kpprzrdr.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The file attachment filter component included with the instance of
Symantec Mail Security installed on the remote Windows host is
reportedly affected by a buffer overflow vulnerability that can be
triggered when handling attachments of various types.

By sending an email with a specially crafted attachment through a
vulnerable server, an attacker may be able to execute arbitrary code
subject to the privileges under which the affected daemon runs.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef26d036");

  script_set_attribute(attribute:"solution", value:
"If using Symantec Mail Security for Domino, upgrade to version 7.5.11
/ 8.0.8.

If using Symantec Mail Security for Microsoft Exchange, upgrade to
version 6.0.12 / 6.5.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:mail_security");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("sms_for_domino.nasl", "sms_for_msexchange.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

dirs = make_array(
  "Domino", "\Verity\Bin\",
  "Exchange", "\SMSMSE\*\Server\Verity\bin\"
);

# Ensure that the affected software is installed.
backend = NULL;
foreach type (keys(dirs))
{
  if (get_kb_item("SMB/SMS_" + type + "/Installed"))
  {
    backend = type;
    break;
  }
}
if (isnull(backend)) exit(0, "Neither Symantec Mail Security for Domino or Exchange is installed on the remote host.");

# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

# Try to connect to server.

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
base = get_kb_item_or_exit("SMB/SMS_" + backend + "/Path");
share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
dir = dirs[backend];
file = "kpprzrdr.dll";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Failed to connect to " + share + " share.");
}

# Try and read one of the affected files.
fh = FindFile(
  file:path + dir + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '" + base + dir + file + "'.");
}

version = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();
if (isnull(version)) exit(1, "Failed to extract the file version from '" + base + dir + file + "'.");

# Check if the DLL file is vulnerable.
fix = 10.9.1.0;
ver = join(version, sep:".");
if (ver_compare(ver:ver, fix:fix) >= 0)
  exit(0, "The Symantec Mail Security for "+backend+" install includes '"+file+"' "+ver+" and thus is not affected.");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  Product           : Symantec Mail Security for ' + backend +
    '\n  File              : ' + base + dir + file +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
