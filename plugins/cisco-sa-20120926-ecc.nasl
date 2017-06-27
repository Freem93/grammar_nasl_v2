#TRUSTED 8113c2cd04895031da8414e26de797b3951bee3340fbaea8dfa152bcab48e0c385adb659834a8004bc5ce16bdcd4a0e82d10e249e841cc2247decd02a87480ef16defe5dd5e38857cba8561fbcd74c9210749854ad778b031cb73e74d240cba066ddc6eee5606e2d11411f5044a73c50ef1eeb789612cfd7ae22d25c0b1bd5332a3f4416d1cef3fa5e653af7491074a04e67962718c2c8dbad4745a535cc0c016d46393173a61f3cd3a668481b19dc9e17dd28edcd2c9bda5073f1bd0325e38ed9806b42fa5d6d63b308b05606bde82cf203e735a454d7c301943de145a314724a1ad73524de64543dbce7661b3777078899d51b5a4419808f489915d0a8ec765b37b0191c31d6fddfef4d2fbbd4c2d579ceadb1fc8de19f6480edef4999b82233f53bef6357737f8cd4c5d2c1d0bf029076a082524fcf7078a50910c5e57d00b613c2becb2b6abeb5753c37d4a654c7ca1fa435a3dbb607f40be346eb730c1eccde1b808031a984de6b1ee98877b8741771336e154d3f9bba9b04c81a9f59a49036a43f874a7ec92a903105ceacbc4447ba7f562e3fd8af2c447b88f48875748bc30fc69ed11a53f51f32a023933e680520ec2cec63d5183d10075b7059b6e4cd0abe734da51dca59b93758714ae02d9e0a78970b332db74861e05050ce7c613a326d8fe95f14e54ea482b3a9af2282c06e128b23cc7e173c591969128efb79
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-ecc.
# The text itself is copyright (C) Cisco
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67204);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-4622");
  script_bugtraq_id(55701);
  script_osvdb_id(85821);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty88456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-ecc");
  script_xref(name:"IAVA", value:"2012-A-0154");

  script_name(english:"Cisco Catalyst 4500E Series Switch with Cisco Catalyst Supervisor Engine 7L-E Denial of Service Vulnerability (cisco-sa-20120926-ecc)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Catalyst 4500E series switch with Supervisor Engine 7L-E contains
a denial of service (DoS) vulnerability when processing specially
crafted packets that can cause a reload of the device. Cisco has
released free software updates that address this vulnerability.
Workarounds that mitigate this vulnerability are not available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-ecc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca6933a5"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-ecc."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/08");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '15.0(2)XO' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"WS-X45-SUP7L-E ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
