#TRUSTED 2637facd7d87f27d26c459ab86de50c8d6d259115e693ce3a026e8820cb165f265e57c47bad8852cb53e6f649439cfeb5b727bd31c62ff9186b8a7904da98768fab14c3bd24d7326d406bd78f4ee97c7bfc1b30eeb4337d909b50a30e20e61574b715f01673a5fe5b96cfde9521f5577fb8e6c897c5a3bd3c61e80a7bf455b0de776ffd7b2ebf911f8f950e658d462ba20cb087acfa33ade126460da1fcf9a9946fd909a8c7a7f6f574753e44bab3c68815be94abfedbdad3ea5fa6d36d666368eac3be05bd3f8834c6eceb2b16f885edc06ddb66009d34370aafd45cb6746596b8a0cf7a45f48dd0cc76cf8b513f8765115a045a1dcc31da8a237746e1271ed7725fd2d3afb2a11cf07261a07cc773447b16a1e1f6f73de15462e8821dc06119f25afd5d4fa2cfe7da819295c7042b36a8fad9c28f584a84498f3909bf28eeab153c4b0d00a4a0bf2cf485bb84a3ca07daceb684211664d2bed8ff3699854f961d253aa6a23b348f944f5b096c1d8ee28af2fba1eacc927b1af1846978935110637154205e5928677c7082899d74d494d7b76fba62f2e2a8f2b74d7fd1ead1497d30c89090d0a955f63b8d5069417bf64674e79ff39f9bd28d101848f0c87220cdfbfe6cae1f012d47efd66d7b126b82b9373472f2aae0ae045565a509babfe8964ecf051edb29706eb257655cb6332535b58d1858207adaa80eb3eaac5b926
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82584);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0635", "CVE-2015-0636", "CVE-2015-0637");
  script_bugtraq_id(73339, 73341, 73343);
  script_osvdb_id(119946, 119947, 119948);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ani");

  script_name(english:"Cisco IOS Autonomic Networking Infrastructure Multiple Vulnerabilities (cisco-sa-20150325-ani)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by the following vulnerabilities in
the Autonomic Networking Infrastructure (ANI) :

  - A flaw exists in the ANI implementation due to failing
    to properly validate Autonomic Networking (AN) response
    messages. An unauthenticated, remote attacker, using
    crafted AN messages, can boot the device into an
    untrusted automatic domain, thus gaining limited control
    of the AN node and disrupting access to legitimate
    domains, resulting in a denial of service.
    (CVE-2015-0635)

  - A denial of service vulnerability exists in the ANI due
    to improperly handling AN messages that can reset the
    finite state machine. An unauthenticated, remote
    attacker, using a specially crafted AN message, can
    spoof an existing AN node, allowing disruption of access
    to the automatic domain. (CVE-2015-0636)

  - A denial of service vulnerability exists in the ANI due
    to improperly validating received AN messages. An
    unauthenticated, remote attacker, using crafted AN
    messages spoofing the device, can cause the device to
    reload. (CVE-2015-0637)

Note that these issues only affect devices with ANI enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?536f8474");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37811");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37812");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=37813");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco Security Advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = get_kb_item_or_exit("Host/Cisco/IOS/Model");

if (
  model !~ '^ASR90(1S?|3)$' &&
  model !~ '^ME-3(600X?|800)-'
) audit(AUDIT_HOST_NOT, 'affected');

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
if ( ver == '12.2(33)IRD1' ) flag++;
if ( ver == '12.2(33)IRE3' ) flag++;
if ( ver == '12.2(33)SXI4b' ) flag++;
if ( ver == '12.2(44)SQ1' ) flag++;
if ( ver == '12.4(25e)JAM1' ) flag++;
if ( ver == '12.4(25e)JAP1m' ) flag++;
if ( ver == '12.4(25e)JAZ1' ) flag++;
if ( ver == '15.0(2)ED1' ) flag++;
if ( ver == '15.2(1)EX' ) flag++;
if ( ver == '15.2(2)JB1' ) flag++;
if ( ver == '15.3(2)S2' ) flag++;
if ( ver == '15.3(3)JA1n' ) flag++;
if ( ver == '15.3(3)JAB1' ) flag++;
if ( ver == '15.3(3)JN' ) flag++;
if ( ver == '15.3(3)JNB' ) flag++;
if ( ver == '15.3(3)S' ) flag++;
if ( ver == '15.3(3)S1' ) flag++;
if ( ver == '15.3(3)S2' ) flag++;
if ( ver == '15.3(3)S2a' ) flag++;
if ( ver == '15.3(3)S3' ) flag++;
if ( ver == '15.3(3)S4' ) flag++;
if ( ver == '15.3(3)S5' ) flag++;
if ( ver == '15.4(1)S' ) flag++;
if ( ver == '15.4(1)S1' ) flag++;
if ( ver == '15.4(1)S2' ) flag++;
if ( ver == '15.4(1)S3' ) flag++;
if ( ver == '15.4(2)S' ) flag++;
if ( ver == '15.4(2)S1' ) flag++;
if ( ver == '15.4(2)S2' ) flag++;
if ( ver == '15.4(3)S' ) flag++;
if ( ver == '15.4(2)SN' ) flag++;
if ( ver == '15.4(2)SN1' ) flag++;
if ( ver == '15.4(3)SN1' ) flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup62191, CSCup62293, and CSCup62315' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(0);
}
else audit(AUDIT_HOST_NOT, "affected");
