#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72832);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_cve_id("CVE-2007-1748");
  script_bugtraq_id(23470);
  script_osvdb_id(34100);
  script_xref(name:"CERT", value:"555920");
  script_xref(name:"EDB-ID", value:"3737");
  script_xref(name:"EDB-ID", value:"3740");
  script_xref(name:"MSFT", value:"MS07-029");

  script_name(english:"MS07-029: Vulnerability in Windows DNS RPC Interface Could Allow Remote Code Execution (935966) (uncredentialed check)");
  script_summary(english:"Checks version of Microsoft DNS Server");

  script_set_attribute(attribute:"synopsis", value:
"The DNS server running on the remote host is potentially affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Microsoft DNS Server
running on the remote host contains an issue that could allow an
attacker to execute arbitrary code with SYSTEM privileges.  To exploit
this issue, an attacker needs to connect to the DNS server RPC interface
and send malformed RPC queries.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS07-029");
  script_set_attribute(attribute:"solution", value:"Microsoft has released patches for Windows 2000 and 2003 Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS07-029 Microsoft DNS RPC Service extractQuotedChar() Overflow (SMB)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("ms_dns_version.nasl");
  script_require_keys("ms_dns/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("ms_dns/version");
port = 53;
fix = NULL;

# Windows Server 2003
if (version =~ "^5\.2\.3790\.")
{
  # SP2
  if (
    ver_compare(ver:version, fix:"5.2.3790.3959") >= 0 &&
    ver_compare(ver:version, fix:"5.2.3790.4059") == -1
  )
    fix = "5.2.3790.4059";

  # SP1
  else if (ver_compare(ver:version, fix:"5.2.3790.2915") == -1)
    fix = "5.2.3790.2915";
}

# Windows 2000
else if (version =~ "^5\.0\.2195\." && ver_compare(ver:version, fix:"5.0.2195.7135") == -1)
  fix = "5.0.2195.7135";

else
  audit(AUDIT_LISTEN_NOT_VULN, "Microsoft DNS Server", port, version, "UDP");


if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, proto:"udp", extra:report);
}
else security_hole(port:port, proto:"udp");
