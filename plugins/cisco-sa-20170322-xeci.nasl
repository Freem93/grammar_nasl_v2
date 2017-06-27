#TRUSTED 8435207faffa3db4f2027f0afde1bf8f52fca9b75dd1a9010038d1707deacf01b5fad22092a0af8ee04af8ab024a9f44bf06ab15ae170c5c5117bd3dc843020df98d0baf37cdb138245a71bdb023603c70d6641241f4b3428cfbfd61e9d8d10fbf6997aa986b72b3c9de0f18391f45cb42d66cc9f2cb8b37985698175de7f763a3339a58a0f7b0d75c629bb9d9f8744e97d5a77e68387d8e760d9bbd75c6782d6e55ef4e52b7e7ee97e544f4a071f4f145a9d47dcf0d2e3d94407cf2e84f54568b2890945a2c28c9adcaf9027e94fb3ff6aad3ca2c1c45c9a3bde767a95417bd416c2df3facbec836851b9a3d22da43572b23da26618217f1fbb28fcecf21d30dfaa5bcc82fdc1a3c7a948b11679c0bf73788a480075671fb10f2106ae42b52f9f552871aec8a52d66c39c049dea94bf05e5d027d9df5f2fec32a3fa875f24f831ee6bd6fbdc42e98d1ae946418bc021a6de9737e539056f3df504f157f1134a0d6a0f922a7dff9af3a860e15b74859ca87342d8f9e039adcf7b5849fde2bd25c2cebcbf3113640a4a5865715ee5de1a40cb1ffbb9d84b709576d5117d7976e429b9da7f2638013ee4a76adf473de40f6d06e35f978cc4b04243285f557c7701346ac14ae678bfe26053598c15d476c0d18fadc019a31d339c2ad62b0c1b455dda3afbc26af5b7f6d7968d72d7d4213114f923fb4abe6d52685bd25569e707bb
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99032);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/31");

  script_cve_id("CVE-2017-3858");
  script_bugtraq_id(97009);
  script_osvdb_id(154193);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy83069");
  script_xref(name:"IAVA", value:"2017-A-0083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170322-xeci");

  script_name(english:"Cisco IOS XE HTTP Parameters Command Injection (cisco-sa-20170322-xeci)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by an command injection
vulnerability due to insufficient validation of user-supplied HTTP
input parameters. An authenticated, remote attacker can exploit this
issue, via a specially crafted request, to execute arbitrary commands
with root level privileges.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170322-xeci
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33e0fa8b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy83069");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuy83069.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag = 0;
override = 0;

if (ver == "16.2.1") flag = 1;

cmds = make_list();
# Confirm whether a device is listening on the DHCP server port
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  pat = "HTTP server status:\s+Enabled";

  buf = cisco_command_kb_item("Host/Cisco/Config/show ip http server status", "show ip http server status");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:pat, string:buf, icase:TRUE))
    {
      cmds = make_list(cmds, "show ip http server status");
      flag = 1;
    }
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
  if (!flag && !override) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", ver);
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : ver,
    bug_id   : "CSCuy83069",
    cmds     : cmds
  );
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
