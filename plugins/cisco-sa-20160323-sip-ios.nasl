#TRUSTED 521204c5c4f769456b3dfee5ca685a009b2baf0975ff2999ff3c2ea77f2c2f5b0f39652809e0ebf1f1e7a28661b91bbcb0938528ac6eec614d6731341538424f8bcd2c60024c1472934d89a10833ccd1954a9223764e62acf523bcafd01c82c1eb8b80d18369577dc630572e9f382f0aa63326d886d9f27b4664e80f2efc8606dacccec02de425ff7a2e132749b159eb5eb15d95ad9ee13659220ad31e2014503993d1952799091075af826aa1878f2c43901ae3fcc063d48a981115146f825ec34a4b2e04834409635cf5db36cf6e2ce96c2642cf650ca3187dcbb51606197e9a5b41e363ddada0a44622aaa4c01951ad06c8330411acc7ce48883f45539e557b13619acdfd46bdc79efbbad55d949dfabb43d8a456eaeb80bb41462ca3ec1186c334b5bbc829f2efaf5a7e125f19668c51a5d48a8b84a42e4cf5eac5fc5ab6e935d710ae9a18edfac59fbb1a2df809f991e2655dbea34b6c5d335c06a1d0a32cb3c558b2137059889f28c59ebe39d4c21582d6013f49573a7d0bdbd1196821dc5eb4cffc36286d56ec3c95670faeb41e338fb8389634e26852b75958154497c674d991093f72adea791dbde92a3ef6bb44193343c73d6607d23b61ec9244382efe256f43a673c10c4fdbc45deb194cead3e56f6c2f46f24da2117cb493b8b8de3533eb60567ad9be82dd4724fac2d9ec141d26ae7d0ed8bfbd66fc61c29ccc
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90310);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/08/29");

  script_cve_id("CVE-2016-1350");
  script_osvdb_id(136248);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco IOS SIP Memory Leak DoS (CSCuj23293)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Session Initiation Protocol (SIP) gateway implementation due to
improper handling of malformed SIP messages. An unauthenticated,
remote attacker can exploit this, via crafted SIP messages, to cause
memory leakage, resulting in an eventual reload of the affected
device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc3f527");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCuj23293");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

affected = make_list(
  "15.3(3)M",
  "15.3(3)M1",
  "15.3(3)M2",
  "15.3(1)S1",
  "15.3(1)S2",
  "15.3(2)S0a",
  "15.3(2)S2",
  "15.3(1)T",
  "15.3(1)T1",
  "15.3(1)T2",
  "15.3(1)T3",
  "15.3(1)T4",
  "15.3(2)T",
  "15.3(2)T1",
  "15.3(2)T2",
  "15.3(2)T3",
  "15.3(2)T4",
  "15.4(1)CG",
  "15.4(2)CG",
  "15.4(1)T",
  "15.4(1)T1",
  "15.4(2)T"
);

flag = 0;
foreach badver (affected)
{
  if (badver == ver)
  {
    flag = 1;
    break;
  }
}

# Configuration check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = " CCSIP_(UDP|TCP)_SOCKET(\r?\n|$)";
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_processes_include_sip","show processes | include SIP ");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
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
    order  = make_list('Cisco bug ID', 'Installed release');
    report = make_array(
      order[0], "CSCuj23293",
      order[1], ver
    );
    
    if (report_verbosity > 0)
      report = report_items_str(report_items:report, ordered_fields:order) + cisco_caveat(override);
    else # Cisco Caveat is always reported
      report = cisco_caveat(override);
    security_hole(port:0, extra:report);
    exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
