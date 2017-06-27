#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(96630);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/01/23 17:47:50 $");

  script_cve_id(
    "CVE-2016-9676",
    "CVE-2016-9677",
    "CVE-2016-9678",
    "CVE-2016-9679",
    "CVE-2016-9680"
  );
  script_bugtraq_id(95620);
  script_osvdb_id(
    150222,
    150223,
    150224,
    150225,
    150226
  );
  script_xref(name:"IAVB", value:"2017-B-0007");

  script_name(english:"Citrix Provisioning Services 7.x < 7.12 Multiple Vulnerabilities (CTX219580)");
  script_summary(english:"Checks version of StreamProcess.exe");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Citrix Provisioning Services running on the remote
Windows host is either 7.x prior to 7.12 or 7.6 LTSR prior to 7.6.4
LTSR. It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists due to an
    overflow condition caused by improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-9676)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to disclose
    kernel address information. (CVE-2016-9677)

  - A remote code execution vulnerability exists due to a
    use-after-free error. An unauthenticated, remote
    attacker can exploit this to dereference already freed
    memory, resulting in the execution of arbitrary code.
    (CVE-2016-9678)

  - A remote code execution vulnerability exists due to a
    function pointer overwrite error. An unauthenticated,
    remote attacker can exploit this to execute arbitrary
    code. (CVE-2016-9679)

  - An information disclosure vulnerability exists that
    allows an unauthenticated, remote attacker to disclose
    kernel memory. (CVE-2016-9680)");
  script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX219580");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Provisioning Services version 7.12 or later. If the
7.6 LTSR version is in use, then upgrade to version 7.6.4 LTSR.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:provisioning_services");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

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

if (prodversion =~ "^7\.6\.[0-3]([^0-9]|$)") fix = '7.6.4';
else if (prodversion =~ "^7\.([0-57-9]|1[01])([^0-9]|$)") fix = '7.12';
if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  File              : ' + path + "StreamProcess.exe" +
    '\n  Installed version : ' + fileversion +
    '\n  Fixed version     : ' + fix + '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else exit(0, "The file version of '"+path+"StreamProcess.exe' is "+fileversion+" and thus it is not affected.");
