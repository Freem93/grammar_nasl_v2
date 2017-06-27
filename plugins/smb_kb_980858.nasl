#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46017);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/07 15:07:05 $");

  script_cve_id("CVE-2010-0478");
  script_bugtraq_id(39356);
  script_osvdb_id(63726);
  script_xref(name:"MSFT", value:"MS10-025");

  script_name(english:"MS10-025: Vulnerability in Microsoft Windows Media Services Could Allow Remote Code Execution (980858) (uncredentialed check)");
  script_summary(english:"Checks the version of Windows Media Services.");

  script_set_attribute(attribute:"synopsis", value:
"The remote media service is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Windows Media Services running on the remote host is
affected by a stack-based buffer overflow condition in the Unicast
Service component due to improper sanitization of user-supplied input.
An unauthenticated, remote attacker can exploit this, via specially
crafted transport information packets, to execute arbitrary code.

Note that Windows Media Services is not enabled by default on Windows
2000 Server. For the server to be vulnerable, it would have to be
configured as a streaming media server by adding the Windows Media
Services component in the Windows Components Wizard.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms10-025");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Windows Media Services ConnectFunnel Stack Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows_2000");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");

  script_dependencies("windows_media_services_detect.nasl", "os_fingerprint.nasl");
  script_exclude_keys("Host/not_windows");
  script_require_keys("ms-streaming/1755/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");

os = get_kb_item_or_exit("Host/OS");
if ("Windows 2000" >!< os) audit(AUDIT_OS_NOT, "Windows 2000");

port = 1755;
version = get_kb_item("ms-streaming/"+port+"/version");
if (isnull(version))
  audit(AUDIT_NOT_LISTEN, 'Windows Media Services', port);

fixed_version = "4.1.0.3939";
if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  report =
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fixed_version +
    '\n';

  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
}
else
  audit(AUDIT_LISTEN_NOT_VULN, 'Windows Media Services', port, version);
