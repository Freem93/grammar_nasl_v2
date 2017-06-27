#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(59018);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/23 15:31:52 $");

  script_cve_id("CVE-2012-4068");
  script_bugtraq_id(53330);
  script_osvdb_id(81664);

  script_name(english:"Citrix Provisioning Services SoapServer RCE (CTX133039)");
  script_summary(english:"Checks version of StreamProcess.exe.");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote Windows host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Provisioning Services running on the remote
Windows host is affected by a remote code execution vulnerability in
the SoapServer service due to an overflow condition caused by improper
validation of user-supplied input when parsing date and time strings.
An unauthenticated, remote attacker can exploit this, via a specially
crafted packet, to cause a denial of service condition or the
execution of arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX133039");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant hotfix as referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");

  script_dependencies("citrix_provisioning_services_detect.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Citrix/Provisioning_Services/Version", "SMB/Citrix/Provisioning_Services/Path", "SMB/Citrix/Provisioning_Services/StreamProcess.exe");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Path");
prodversion = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/Version");
fileversion = get_kb_item_or_exit("SMB/Citrix/Provisioning_Services/StreamProcess.exe");

# Unless we're paranoid, make sure the service is running
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit('SMB/svc/StreamService');
  if (status != 1)
    exit(0, 'The Citrix Streaming service is installed but not active.');
}

fix = NULL;
ver = split(prodversion, sep:'.', keep:FALSE);
for (i=0; i < max_index(prodversion); i++)
  ver[i] = int(ver[i]);

if (ver[0] < 5 || (ver[0] == 5 && ver[1] < 6)) fix = '6.1.0.1082';
if (prodversion =~ '^5\\.6\\.' && ver_compare(ver:fileversion, fix:'5.6.3.1349') == -1) fix = '5.6.3.1349';
else if (prodversion =~ '^6\\.0\\.0$' && ver_compare(ver:fileversion, fix:'6.0.0.1083') == -1) fix = '6.0.0.1083';
else if (prodversion =~ '^6\\.1\\.0$' && ver_compare(ver:fileversion, fix:'6.1.0.1082') == -1) fix = '6.1.0.1082';
if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + "StreamProcess.exe" +
      '\n  Installed version : ' + fileversion +
      '\n  Fixed version     : ' + fix + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, "The file version of '"+path+"StreamProcess.exe' is "+fileversion+" and thus it is not affected.");
