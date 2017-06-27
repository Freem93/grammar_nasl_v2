#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(51664);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2017/01/26 14:48:46 $");

  script_bugtraq_id(45914);
  script_osvdb_id(70597);
  script_xref(name:"EDB-ID", value:"17456");
  script_xref(name:"ZDI", value:"ZDI-11-023");

  script_name(english:"Citrix Provisioning Services StreamProcess.exe 0x40020010 Packet Handling RCE");
  script_summary(english:"Checks version of StreamProcess.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application running that is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the StreamProcess.exe component included with the
Citrix Provisioning Services installation running on the remote
Windows host fails to validate user-supplied input in a packet type of
0x40020010 before copying it into a fixed length buffer on the stack.
An unauthenticated, remote attacker can exploit this, via a specially
crafted 0x40020010 packet sent to UDP port 6095, to execute arbitrary
code on the remote host with SYSTEM privileges.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-023");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2011/Jan/382");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX127149");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-691");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Citrix Provisioning Services 5.6 streamprocess.exe Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_provisioning_services_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Citrix/Provisioning_Services/Version", "SMB/Citrix/Provisioning_Services/Path", "SMB/Citrix/Provisioning_Services/StreamProcess.exe");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

path = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Path");
prodversion = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Version");
fileversion = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/StreamProcess.exe");

# Unless we're paranoid, make sure the service is running
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/StreamService');
  if (status != SERVICE_ACTIVE)
    exit(0, 'The Citrix Streaming service is installed but not active.');
}

# Set the fix value based on the version that is installed
if (prodversion =~ '^5\\.1\\.0$') fix = '5.1.0.3009';
else if (prodversion =~ '^5\\.1\\.1$') fix = '5.1.1.3010';
else if (prodversion =~ '^5\\.1\\.2$') fix = '5.1.2.3008';
else if (prodversion =~ '^5\\.6\\.') fix = '5.6.1.1045';
else fix =
  'Citrix Provisioning Services must be upgraded to a supported version' +
  '  before a patch can be applied.';

if (
  prodversion =~ '^[0-4]\\.' ||
  prodversion =~ '^5\\.0\\.' ||
  (
    (prodversion =~ '^5\\.1\\.0$' && ver_compare(ver:fileversion, fix:'5.1.0.3009') == -1) ||
    (prodversion =~ '^5\\.1\\.1$' && ver_compare(ver:fileversion, fix:'5.1.1.3010') == -1) ||
    (prodversion =~ '^5\\.1\\.2$' && ver_compare(ver:fileversion, fix:'5.1.2.3008') == -1) ||
    (prodversion =~ '^5\\.6\\.' && ver_compare(ver:fileversion, fix:'5.6.1.1045') == -1)
  )
)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + "\StreamProcess.exe" +
      '\n  Installed version : ' + fileversion +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, "The file version of '"+path+"StreamProcess.exe' is "+fileversion+" and thus it is not affected.");
