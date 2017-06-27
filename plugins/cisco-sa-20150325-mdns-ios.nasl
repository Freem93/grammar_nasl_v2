#TRUSTED 821a4a1717a2075c4f94956c507fee8464f2642a728f37c6601c52b9556fa95631995e90b6eab053b4859d53360a543d286ca01d45df05ac651fd81347f9271eba7b765dbb16e4ba2184e9eb4b2cd9f152fadd10575a8c68010085f74a04d314a82009db389202ca5ac23eccb5118c0a010d9bb979b5639d8d69eb63b0043f8c59567ba46de238f7531a0f4f49ec0e63a842cf7e4ce33a6086cdf33e46e41bb18bd2d35e277cdc6bcfaf72ccb947c300cb7bee1a6be832908e4277f7d960f554eaef851efb7ac48b1a7c36f4cf3b5f90d5c9efccfd4447a89729671ded619bfd6881137c03f08a5f663d5987c9e8cad7051fc0241a14bca21158737c9f47a2354a226bf367152cc8854cf35ec7fb84cfd38155ed8876f7cf86cf2213835b57cd8fb62ef8534acc65ea5978013036103d37d8bc29d033a3764da30b1f7714e2bfd0d827a663c08cb87c1b8cdd6a435da5ce0e69fe45c1baef88d62794b6f5e4917d803c81cbc372849acd0d59450ddd3201ca54e7c302fa70f9b05004b7a1204da8f3edb789f104cf6015597103cc7d29276d51676da4e760cad3e42db4e28650ecc02e0d94f4ad1ec420f2d1171709723fd3c482cd717d7d2d29a852b60e902ce3fc7f3c57761c882bcaef34e620be110824478bb63fdec900197a7fa06ba5393ef9f8181dab9382bd66397537004e9c2bf951fe9135511f1e1ee9c31c0f548b
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82572);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0650");
  script_bugtraq_id(73335);
  script_osvdb_id(119949);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup70579");
  script_xref(name:"CISCO-SA",value:"cisco-sa-20150325-mdns");

  script_name(english:"Cisco IOS Software mDNS Gateway DoS");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of Cisco IOS software
that is affected by a vulnerability in the multicast DNS gateway
component due to improper validation of mDNS packets. A remote,
unauthenticated attacker, by sending crafted packets to UDP port 5353,
can exploit this to cause a device reload, leading to a denial of
service.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCup70579");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff1e945");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37820");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCup70579.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
flag = 0;
override = 0;

# Per advisory:
versions = make_list(
  "12.2IRD",
  "12.2(33)IRD1",
  "12.2IRE",
  "12.2(33)IRE3",
  "12.2SQ",
  "12.2(44)SQ1",
  "12.2SXI",
  "12.2(33)SXI4b",
  "12.4JAM",
  "12.4(25e)JAM1",
  "12.4JAP",
  "12.4(25e)JAP1m",
  "12.4JAZ",
  "12.4(25e)JAZ1",
  "15.0ED",
  "15.0(2)ED1",
  "15.1SY",
  "15.1(2)SY",
  "15.1(2)SY1",
  "15.1(2)SY2",
  "15.1(2)SY3",
  "15.2E",
  "15.2(1)E",
  "15.2(1)E1",
  "15.2(1)E2",
  "15.2(1)E3",
  "15.2(2)E",
  "15.2EX",
  "15.2(1)EX",
  "15.2JB",
  "15.2(2)JB1",
  "15.3JA",
  "15.3(3)JA1n",
  "15.3JAB",
  "15.3(3)JAB1",
  "15.3JN",
  "15.3(3)JN",
  "15.3JNB",
  "15.3(3)JNB",
  "15.3S",
  "15.3(2)S2",
  "15.3(3)S",
  "15.3(3)S1",
  "15.3(3)S1a",
  "15.3(3)S2",
  "15.3(3)S2a",
  "15.3(3)S3",
  "15.4M",
  "15.4(3)M",
  "15.4(3)M1",
  "15.4(3)M2",
  "15.4S",
  "15.4(1)S",
  "15.4(1)S1",
  "15.4(1)S2",
  "15.4(2)S",
  "15.4(2)S1",
  "15.4(3)S",
  "15.4SN",
  "15.4(2)SN",
  "15.4(2)SN1",
  "15.4(3)SN",
  "15.4(3)SN1",
  "15.4T",
  "15.4(1)T",
  "15.4(1)T1",
  "15.4(1)T2",
  "15.4(2)T",
  "15.4(2)T1"
);

foreach ver (versions)
{
  if (ver == version)
  {
    flag++;
    break;
  }
}

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_socket",
                              "show ip socket");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"(\d+.\d+.\d+.\d+|.*:.*|UNKNOWN|--any--)\s+5353\s", string:buf))
      flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag++;
    override++;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
    '\n  Cisco bug ID      : CSCup70579' +
    '\n  Installed release : ' + version +
    '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
