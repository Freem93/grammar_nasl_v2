#TRUSTED a14a5ad308ead6fdb4bd803dce42c0db3ec840e8895e19c320747d2f1664858513f019748c4e40922e20fd398fcd98faed37adcec57ed49eb66bf2288de38b94a9da43ff5a4765899e33ac6dfb908dc40ee562d7cda1075834aa28da9df598edf7878d322f88de412ab2cab90d798270c3fec60c95a9777ba7c0f677a332e058fe27bbf23440dd8cac532cf30b6af302d54fcc1ad1d79caa9927e91ef5e9cdd3d22618f6895a6a673900a465a6342691cd720bd69cc1858ecd8338289f628b727667c852d870ff2851e6e593c4d768f711d2fd0fd386bc7d7f74534595b82774dec5bb30d1cc244e9cfeb3f975c95d9a4cacccffbae00f03424b29559ac1dd735c6b9c62fd80eeca9bdc3e6656f0b1c7c8ef7ec2763d1934a07e415aad7b53cd2dbd7af1dc4b3ded1704dc21dfd9556a015fcff3ee257c721677c3f90f06249db5f1bd31c33e5487361a883e771cb2a1b10f3b684c42067493bc7904b97d4c8559293c5944b63d04ed077a53a3874ffdaa750a0f46632023f17a88cf0013e75f49baf9607024e5e769110e2da64b837f5cb83f93117602937cf8e1035a7e4f9a8271af43df4bbe3f86a0ffec7b2d1badd27f92fd4cf67f46784a9fbdac28c36f82a7fd0752f687e6e59e42939bc8bfd289b52ce39b5373e28a4e23f853888357f1f82492cde7c2061e1977f4712a71b64cc929ff9344944daf7ef9d4e30cebb2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85125);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/10/04");

  script_cve_id("CVE-2015-0681");
  script_bugtraq_id(75995);
  script_osvdb_id(125122);
  script_xref(name:"CISCO-BUG-ID", value:"CSCts66733");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150722-tftp");

  script_name(english:"Cisco IOS XE Software TFTP DoS (cisco-sa-20150722-tftp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the TFTP server functionality due to incorrect
management of memory when handling TFTP requests. A remote,
unauthenticated attacker can exploit this by sending a large amount of
TFTP requests to cause the remote device to reload or hang, resulting
in a denial of service condition.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150722-tftp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18ef700f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCts66733");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150722-tftp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/30");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCts66733";
fixed_ver = NULL;

if (
  ver =~ "^2\.[56]\." ||
  ver =~ "^3\.[1-5]\.\d+[a-z]?S$"
) fixed_ver = "3.6.0S";

if (
  ver =~ "^3\.[1-3]\.\d+[a-z]?SG$"
)  fixed_ver = "3.4.0SG";

if (
  ver =~ "^3\.2\.\d+[a-z]?SE$"
)  fixed_ver = "3.3.0SE";

if (
  ver =~ "^3\.2\.\d+[a-z]?XO$"
)  fixed_ver = "3.3.0XO";

if (
  ver =~ "^3\.[2-4]\.\d+[a-z]?SQ$"
)  fixed_ver = "Contact Vendor";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

flag     = TRUE;
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TFTP Check
  #  Router#show running-config | include ^tftp-server
  #  tftp-server flash:c2800nm-adventerprisek9-mz.124-1
  #  tftp-server flash:
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"tftp-server flash:", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}
else override = TRUE;

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because TFTP is not enabled");

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
