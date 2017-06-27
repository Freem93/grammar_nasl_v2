#TRUSTED 23c08ef53c520652814504148a0f41fbba21e44390e94d57089f0ddac277ddcc2cb149cc21ccf285d8955d0872479b32024c179bfba74b98cdf6e802391cf3d1a9d024befe3dddaf938a62dc1b5839f7da5f9533737715b01ccb92186e612e56099e50696a1f9890fc9f97a8f5a277b3e5cf60b9e5a944e91d9ac25395cd6d383cf6b70848a93ddfc5c5baf16b6230a61a7f028f8713419dcb08a192708a67fb977b5d2f18577d4c421e97092e2121a7af88b7abc227e72025a6435393b67361d19a9435af9023597416198af858fde4d0f4f6468563a41c62f0aa7d458b9387c1dc5115e506efae525a38879ee4fff650b84692296088b03f921ca1f77b6beca4aa8d079ee3eb7e94e5eeece3f7c27ea9cf49f6192899ff658b0a25517ed0b560e1c067dc4f9415302051de12d94b6bc0e9892486ad0562ce7e4450a87a6dcae722cfdc589e3a7b0c8e5b132bc0a39e642c2bc3f9138e71609edafc70eaac85b282f6b5a14724efca67261b658d172b4c76fca3465964bcba4d35c275e7225544f563455e4eebb456f10172c360a4cf42d5f54074d5b4badf5a1ac40ef624f756569b22c90908e1e16aad8e86de65c68cda635b35fa504376280c5bdd65e7c31eb68776149f7075fca20fad212dc4f828f7d5dee653df19e1b001ffe6ac4b4be60e53a01c7df738aeab452dbdf700439cc72a974eea82d819ebcab5db6ea1f9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82585);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-0635", "CVE-2015-0636", "CVE-2015-0637");
  script_bugtraq_id(73339, 73341, 73343);
  script_osvdb_id(119946, 119947, 119948);
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62191");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62293");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup62315");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-ani");

  script_name(english:"Cisco IOS XE Autonomic Networking Infrastructure Multiple Vulnerabilities (cisco-sa-20150325-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by the following
vulnerabilities :

  - A flaw exists in the ANI due to failing to properly
    validate Autonomic Networking (AN) messages. This could
    allow a remote attacker to spoof an Autonomic Networking
    Registration Authority (ANRA) response and gain elevated
    privileges or cause a denial of service. (CVE-2015-0635)

  - A flaw exists in the ANI due to imporperly handling AN
    messages. This could allow a remote attacker, with a
    specially crafted AN message, to disrupt autonomic
    domain services. (CVE-2015-0636)

  - A flaw exists in the ANI due to improperly validating AN
    messages. This could allow a remote attacker, with a
    specially crafted An message, to cause the device to
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

model = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  model !~ '^ASR90(1S?|3)$' &&
  model !~ '^ME-3(600X?|800)-'
) audit(AUDIT_HOST_NOT, 'affected');

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

fix = '';
flag = 0;

# Check for vuln version
if (
  ver =~ "^3\.10(\.[0-5])?S([^EG]|$)" ||
  ver =~ "^3\.11(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.12(\.[0-3])?S([^EG]|$)" ||
  ver =~ "^3\.13\.0?S([^EG]|$)"
)
{
  fix = "3.13.1S";
  flag++;
}

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

if (fix && flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCup62191, CSCup62293, and CSCup62315' +
      '\n  Installed release : ' + ver +
      '\n  Fixed release     : ' + fix +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
    exit(0);
  }
  else security_hole(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
