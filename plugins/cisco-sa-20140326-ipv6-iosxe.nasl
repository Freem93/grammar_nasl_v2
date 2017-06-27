#TRUSTED aab9a2537b60f5a5957f1d683546519c66e49c688bd50df8c7320c03477e342047f1176401c15f3f75508fbd5e7f5cbd91ff8d52aff23c2f0b88d18923f50657d3a808e7117501daa8bf0f861fcf003f57b6b8ef6715f28220e3ae11608c7c45853a79a635ae7fca9d9bb5938c4ec85b5894902df37fc8b498e25f4bc2883c6e5f6f226a6e625dc13f0922a8b963c2f1b225c2d05abdb37b9a94e8a16ddfec0896cfcc2aa371e5b9a16e40d9581cbd06681cdda0b82baed08065086fd026efe7b8ed140bb5a7d228b5a4c8203e0bdb42debd08331abf30006c9b298c16adfd44f93b729e7d1a71bb2982f7ac228e33b0389c9a828a7610d68ad66cee269b88d25d8b9d0d775b8060502d50671114a6128eb8510ac8aed257d1dc22c0d93354e7b8575bbe80d1f4df9fb5b3488d653dbe6f163f3525dd44e5dfd837626ee71742fe06e668fea1f9d3f5aa993100d68855921c1c575a4321730ca53928fb92072a6c440ce3fca4cc618e69810dcf893f5912fee7d4ffa2be1526b37395f3d445873f9704adbacdca649994fd92723a43acb32e7a12b9ce1b1950cb65b9d44dbc9ec09b010716f3dc356c1c0bf891fd35a9ae29abd26902a56d0966bdd45d7792b7fddc1a2841f0b001d5b33247ce8ced91d629cb63303f7a011bd84fb7b9e9dea144efc324bb019dcb734b06133179ee92b68472c1dd1783f7c36d869d208beae4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73343);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2113");
  script_bugtraq_id(66467);
  script_osvdb_id(104968);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui59540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ipv6");

  script_name(english:"Cisco IOS XE Software IPv6 Denial of Service (cisco-sa-20140326-ipv6");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the IPv6 protocol stack. This issue exists due to
improper handling of certain, unspecified types of IPv6 packets. An
unauthenticated, remote attacker could potentially exploit this issue
by sending a specially crafted IPv6 packet resulting in a denial of
service.

Note that this issue only affects hosts with IPv6 enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ipv6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f6aa73d");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33351");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ipv6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}


include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;
report = "";
fixed_ver = "";
cbi = "CSCui59540";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.7xS
if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.2S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.2S';
# 3.10xS
else if (ver == '3.10.0S' || ver == '3.10.1S')
         fixed_ver = '3.10.2S';



if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface", "show ipv6 interface");
    if (check_cisco_result(buf))
    {
      if (preg(multiline: TRUE, pattern:"IPv6\s+is\s+enabled", string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver +
    '\n    Fixed release     : ' + fixed_ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
