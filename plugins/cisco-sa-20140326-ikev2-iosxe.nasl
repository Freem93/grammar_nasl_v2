#TRUSTED 1e0d7b652bb3d6257af8d13f4cc3f44d241a66c87d1ac3c237e9542b84d57e17d62adc585174cbf759c60a48f76c26d15b59a1b0766999fa59e07a28b81d6d236827a4c70b5f2d587f2b9339f77b1b3c697e3c3de44ac16157306a5c24e42f8455721d270d59fe26eefe22ee90849595ad370f794b64e48e1c826bc79b00fa14f29fd6b0e0df6db03b38282353442b0596353aee7a5c74cb783da81b8375b2a84c599e1fce9d85e10a37376cbaadeff6a490b436646bd085ba3b3db4805ab33215a452fca8df97c5b4f3dd2ba035f3e51f46ab5c7b8f3fdd157a654e54cc37d5cfb3a69c52e9ccf448f2efb8fe4c742f6f5c306a52b2f9e7da2c1ad021e0ecbe3b104386227381d1e64bc24e6182029aa6b6e460f06ea27038e828347337d0da574059fd6340e682b511932dfc9660169ad70617a348edfc3806a480c73dd664387e34235f5addaf47e737d195fe285297769f52bfc81276932e93d032ca7905f1e0561d3a7ee5d912c8a32529a6a89b445beeb7ee8b0b285b694f9bd0f4384453bd8d42f3a27dc05059cefde570b20aae26b967c0f8298ab922424d09e984d26ae7d2d4a2388b6e97c2c0f3f46b208e8f66d721aa64066b882911497781f6d3232978ad7f993849278db6e0201482c212ec8e2ff400a7173fc75ea4f38f69503c29f08a48ff954ffac7f6aa09e55b98c9163365cd7bc2c5785c82119908a4bf
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73340);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2108");
  script_bugtraq_id(66471);
  script_osvdb_id(104965);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui88426");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ikev2");

  script_name(english:"Cisco IOS XE Software Internet Key Exchange Version 2 (IKEv2) Denial of Service (cisco-sa-20140326-ikev2)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a denial of service
vulnerability in the Internet Key Exchange Version 2 (IKEv2) module.
An unauthenticated, remote attacker could potentially exploit this
issue by sending a malformed IKEv2 packet resulting in a denial of
service.

Note that this issue only affects hosts when Internet Security
Association and Key Management Protocol (ISAKMP) is enabled.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140326-ikev2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a1b54a0");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=33346");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140326-ikev2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/29");
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

override = 0;
report = "";
cbi = "CSCui88426";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

# 3.2xS
if (ver == '3.2.0S' || ver == '3.2.1S' || ver == '3.2.2S')
         fixed_ver = '3.7.5S';
# 3.3xS
else if (ver == '3.3.0S' || ver == '3.3.1S' || ver == '3.3.2S')
         fixed_ver = '3.7.5S';
# 3.4xS
else if (ver == '3.4.0S' || ver == '3.4.1S' || ver == '3.4.2S' || ver == '3.4.3S' || ver == '3.4.4S' || ver == '3.4.5S' || ver == '3.4.6S')
         fixed_ver = '3.7.5S';
# 3.6xS
else if (ver == '3.6.0S' || ver == '3.6.1S' || ver == '3.6.2S')
         fixed_ver = '3.7.5S';
# 3.7xS
else if (ver == '3.7.0S' || ver == '3.7.1S' || ver == '3.7.2S' || ver == '3.7.3S' || ver == '3.7.4S')
         fixed_ver = '3.7.5S';

# 3.3xSG
else if (ver == '3.3.0SG' || ver == '3.3.1SG' || ver == '3.3.2SG')
         fixed_ver = '3.5.2E';
# 3.4xSG
else if (ver == '3.4.0SG' || ver == '3.4.1SG' || ver == '3.4.2SG')
         fixed_ver = '3.5.2E';
# 3.5xS
else if (ver == '3.5.0S' || ver == '3.5.1S' || ver == '3.5.2S')
         fixed_ver = '3.5.2E';
# 3.5xE
else if (ver == '3.5.0E' || ver == '3.5.1E')
         fixed_ver = '3.5.2E';

# 3.3xXO
else if (ver == '3.3.0XO)')
         fixed_ver = '3.6.0E';

# 3.8xS
else if (ver == '3.8.0S' || ver == '3.8.1S' || ver == '3.8.2S')
         fixed_ver = '3.10.1S';
# 3.9xS
else if (ver == '3.9.0S' || ver == '3.9.1S')
         fixed_ver = '3.10.1S';
# 3.10xS
else if (ver == '3.10.0S')
         fixed_ver = '3.10.1S';


if (fixed_ver) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"17\s[^\r\n]*\s(500|4500|848|4848)", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_subsys", "show subsys");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ikev2\s+Library", multiline:TRUE, string:buf)) { flag = 1; }
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
