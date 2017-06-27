#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(54922);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/10/27 15:14:57 $");

  script_cve_id(
    "CVE-2011-0548",
    "CVE-2011-1213",
    "CVE-2011-1214",
    "CVE-2011-1215",
    "CVE-2011-1216",
    "CVE-2011-1217",
    "CVE-2011-1218",
    "CVE-2011-1512"
  );
  script_bugtraq_id(
    47962,
    48013,
    48016,
    48017,
    48018,
    48019,
    48020,
    48021
  );
  script_osvdb_id(72705, 72706, 72707, 72708, 72709, 72710, 72711);
  script_xref(name:"CERT", value:"126159");
  script_xref(name:"EDB-ID", value:"17448");
  script_xref(name:"Secunia", value:"44624");

  script_name(english:"IBM Lotus Notes Attachment Handling Multiple Buffer Overflows");
  script_summary(english:"Checks file version of kvgraph.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The file attachment viewer component included with the instance of
Lotus Notes installed on the remote Windows host is reportedly
affected by several buffer overflow vulnerabilities that can be
triggered when handling attachments of various types.

By sending a specially crafted attachment to users of the affected
application and getting them to double-click and view the attachment,
an attacker may be able to execute arbitrary code subject to the
privileges under which the affected application runs.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd613361");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ebc7ee5b");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a86a0423");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b1bb9cc4");
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/LotusNotes-XLS-viewer-heap-overflow");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/178");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/179");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/181");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/May/182");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/archive/1/518120/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21500034");
  script_set_attribute(attribute:"solution", value:
"Either Install Interim Fix 1 for Notes 8.5.2 Fix Pack 2 / 8.5.2 Fix
Pack 3 or upgrade to 8.5.3. Alternatively, disable attachment viewers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Lotus Notes 8.0.x - 8.5.2 FP2 - Autonomy Keyview (.lzh Attachment)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_notes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","lotus_notes_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated","SMB/Lotus_Notes/Installed");
  script_require_ports(139, 445);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("audit.inc");

kb_base = "SMB/Lotus_Notes/";

version = get_kb_item_or_exit(kb_base + 'Version');
path = get_kb_item_or_exit(kb_base + 'Path');

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Split the software's location into components.
base = ereg_replace(string:path, pattern:"^(.+)\\$", replace:"\1");

share = ereg_replace(string:base, pattern:"^([A-Za-z]):.*", replace:"\1$");
path = ereg_replace(string:base, pattern:"^[A-Za-z]:(.*)", replace:"\1");
file = "\xlssr.dll";

# Connect to the share software is installed on.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

# Try and read one of the affected files.
fh = CreateFile(
  file:path + file,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (isnull(fh))
{
  NetUseDel();
  exit(0, "Failed to open '" + base + file + "'.");
}

version = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();
if (isnull(version)) exit(1, "Failed to extract the file version from '" + base + file + "'.");


# Check if the DLL file is vulnerable.
fix = "8.5.23.11191";
ver = join(version, sep:".");
if (ver_compare(ver:ver, fix:fix) >= 0)
  exit(0, "The Lotus Notes install includes '"+file+"' "+ver+" and thus is not affected.");

# Report our findings.
if (report_verbosity > 0)
{
  report =
    '\n  File              : ' + base + file +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
