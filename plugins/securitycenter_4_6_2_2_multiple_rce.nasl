#TRUSTED 10a06220fb0d0754cb6f79983bd94dbd0fc59be9427857391f3f344865ffc490f95ffefbb23128d9d64b93e8bc8729b0a17e6e3c16d191edafe2330790a84ffd721168b7ec2e370b0f303ec65a0d1e65fbbf4be01e88be1e17312d1e2df17d2bd36b2d9faf41a475a3d3a5777e5aae12e2a953088ed5c1522c42495117cd9dedfef7830985e0dc80f047cb98a8378d81e18e11b354c622f870d7489798dc64cb826917b55eee7d5fba2f99af95150a3ccc08a90de7da98adc1719f816b46b7a111616b51821051ef04968a9fbf5bd5bf9a469ab25aecd92eb1d6770996453e0aea606d7fbb2f3edb12fc9f0a5b954c5145b7bf2c6667dd1914823260209ce7486c1f81a670a7f893de07ba1222a6dedbab902d8222589bfe220a1788b929006fff8b334d5c9ca57f846e24914a5a792cc23ea2d9b03b2ceda52ac297f4b79bfc3c584f6108d7d52f68877f857531e3b75fab0e6ae4db251cb58c18ffe5968641a0ab9dd0bd1b459ad0e785e2867f770ea02a549bc8b45fde375008b610c41be770987ee90ef11a31b7b035a953c8235d09fe26d78419ca81297211698c920c6da20008dbd7df43f8210076f83f0c2cec7caf4cb3cf7a67fd9dda66a3cdbd2e2122139167c968161f4b3d90040065744ac4493beae9f4e65f8bf7ae1ffcd90bba55875eede042943fbd986be33d3d5dc2e44f5029967ffc05b9a38eef830b11d7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85183);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/03");

  script_cve_id("CVE-2015-4149", "CVE-2015-4150");
  script_osvdb_id(125210);

  script_name(english:"Tenable SecurityCenter < 5.0.1 Multiple RCE (TNS-2015-10)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is affected by multiple
remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the installation of Tenable SecurityCenter
on the remote host is affected by multiple remote code execution
vulnerabilities :

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a dashboard for another user, to execute
    arbitrary code when the server processes the file.

  - A flaw exists due to improper sanitization of
    user-supplied files during upload functions. An
    authenticated, remote attacker can exploit this, by
    uploading a custom plugin or custom passive plugin with
    a specially crafted archive file name, to execute
    arbitrary code when the server processes the file.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2015-10");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 4.6.2.2 / 4.7.1 / 4.8.2 and
apply the appropriate patch referenced in the vendor advisory.
Alternatively, upgrade to version 5.0.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin");
  script_require_keys("Host/SecurityCenter/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
version = get_kb_item_or_exit("Host/SecurityCenter/Version");
vuln = FALSE;

# Affects versions 4.6.2.2, 4.7.0, 4.7.1, 4.8.0, 4.8.1, 4.8.2 and 5.0.0
if (version =~ "^4\.(6\.2\.2|7\.[01]|8\.[0-2])$")
{
  # Establish running of local commands
  if ( islocalhost() )
  {
    if ( ! defined_func("pread") ) audit(AUDIT_NOT_DETECT, "pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (! sock_g) audit(AUDIT_HOST_NOT, "able to connect via the provided SSH credentials.");
    info_t = INFO_SSH;
  }

  file = "/opt/sc4/src/tools/customPluginUpload.php";
  # Patched MD5 for /opt/sc4/src/tools/customPluginUpload.php
  if (version =~ "^4\.6") fix_md5 = '65bc765ae62d8127c012ec286cabc686'; 
  if (version =~ "^4\.7") fix_md5 = '65bc765ae62d8127c012ec286cabc686';
  if (version =~ "^4\.8") fix_md5 = '5784a4f1e87ab0feb32f82a4dfd84c9b';

  # Check version
  res = info_send_cmd(cmd:"md5sum " + file);
  if (! res) exit(1, "The command 'md5sum "+file+"' failed.");

  if (res !~ '^[a-f0-9]{32}')
    exit(1, "Unable to obtain an MD5 hash for '"+file+"'.");

  if (fix_md5 >!< res)
  {
    vuln = TRUE;
    # 4.6.2.2
    if (version == "4.6.2.2")
      fix = "Apply the 4.6.2.2 patch referenced in the TNS-2015-10 advisory.";
    # 4.7.x
    if (version =~ "^4\.7")
    {
      if (version == "4.7.1")
        fix = "Apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.7.1 and apply the 4.7.1 patch referenced in the TNS-2015-10 advisory.";
    }
    # 4.8.x
    if (version =~ "^4\.8")
    {
      if (version == "4.8.2")
        fix = "Apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
      else
        fix = "Upgrade to version 4.8.2 and apply the 4.8.2 patch referenced in the TNS-2015-10 advisory.";
    }
  }
}
else if (version =~ "^5\.")
{

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i < max_index(ver); i++)
    ver[i] = int(ver[i]);

  if (ver[0] == 5 && ver[1] == 0 && ver[2] < 1)
  {
    vuln = TRUE;
    fix = "5.0.1";
  }
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fix + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
