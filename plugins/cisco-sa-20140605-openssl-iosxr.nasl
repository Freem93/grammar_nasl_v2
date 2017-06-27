#TRUSTED 9385b93f54693ff33a8d6ad6afbb5866c5cf9b883b6f6a6885a6217795e9c67be4e4f53edda389a8a73f46b9571ebcaa094e8a536fa75acfca80cb0cd234db4e48f25b3674dd6d5c0ceb8eb3141021f5081f77b56b4085f150db7f20b5e54034100263b41761c7214fe0c09c75dd26d43a487b532bf8199f2f49b1302b806efba393a570270ecad2bb815a8d8722bf7e149ab2635e69aaa2368f1551fbc1c1a5086e0172d0ad50049b6bc7e4827faebd909c7ef4f3d3dca610aec3aed2d0c1ac5384753e50974343c68bdbd907361189d7d23dc65e2eae2a4259a0090455b449fe1d016e5ea6ee5994b023e0ab778e6b14b4c1b5497ff6e2e0c3ad1aea603fc899905f42cbc8b3c07bbb25690ff2504f18bedfb8092bf53c6409ded75cf46b67ed7f572f34bbb8fb3660b2334cf17ca8dfcee81ee8447625a47afdee3606660fc1877f451f59e7a34d1e0534379e70c977671dd3a696a1b8febfe3b242a01c0ca01fc8dccd9d6b34be9b0d5f602f7009e181f9fdaad3921d5e37c5ab2f11708042e001e9d6e60cd616396419651f825e8bdd0a12a9e48993a0dd3ba5f38e5160a2be404115be10a9efd32f75753675237a46ca9395218177d34831ab9d7396b5f6ccf1e7e7254c1c19edfda74d653f9da95a204773fbd695dc48a183d43ee6b8bc9b80ee1f4e6b948df930cfdddfd8f12b7ba16c59e5899a90d5035af7ec14aa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88990);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/02/26");

  script_cve_id("CVE-2014-0224");
  script_bugtraq_id(67899);
  script_osvdb_id(107729);
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22654");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco IOS XR OpenSSL Security Bypass (CSCup22654)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of IOS XR software that
is affected by security bypass vulnerability in the bundled OpenSSL
library due to an unspecified error that can allow an attacker to
cause the usage of weak keying material, leading to simplified
man-in-the-middle attacks.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d64ee0f");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup22654");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCup22654.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");
override = FALSE;

# all releases from 4.3.1 through 5.2.0 are affected
if (
  !(
    version =~ "^4\.3\.[1-9]" ||
    version =~ "^5\.[01]\."   ||
    version =~ "^5\.2\.0($|[^0-9])"
  )
) audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

if (!isnull(get_kb_item("Host/local_checks_enabled")))
{
  flag = FALSE;
  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all", "show running-config all");

  # Check for services utilizing SSL/TLS
  if (check_cisco_result(buf))
  {
    override = FALSE;

    if (
      # Web UI HTTPS
      preg(string:buf, pattern:"^http server ssl", multiline:TRUE) ||
      # XML Agent
      cisco_check_sections(
        config:buf,
        section_regex:"^xml agent ssl",
        config_regex:'^\\s*no shutdown'
      )
    ) flag++;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = TRUE;
    override = TRUE;
  }

  if (!flag)
    audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");

}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco bug IDs     : CSCup22654' +
    '\n  Installed release : ' + version +
    '\n  Fixed release     : 5.3.0' +
    '\n';
  security_warning(port:0, extra:report+cisco_caveat(override));
}
else security_warning(port:0, extra:cisco_caveat(override));
