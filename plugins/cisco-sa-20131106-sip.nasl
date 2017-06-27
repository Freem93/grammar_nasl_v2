#TRUSTED 1621486c49abaf5ac2889dda06edc100b23066d3ef24e4d618d7ae025a56868fb15aac01fe012acb689d4895645aff4197cc98e2f7af7f56fd6b6eda0603e833e88cf1839a6e4f10c4c2ad590a5a4fca12fbecb37d92004671559f2bcf1ed82f255f60e61534617e766714c48f45984b32ed6f9e565b7cc3b012241d52b5431c8c59c92581f409d022ee9325bb70a454b40cf284a4ef01733824d8ca708702bf8ee7174aec86c3bb442746f8ecf49a1c64965d39a745583fd5fb2bce0811713989bb2e1f30b06b6b11d17772d23aaaefd14f619f41a904fc88b8ba917d43900c003171174a05b82037706f7d7bcb0d60b88c76710fbac7ab37930ce95ad62835692e3614fcad356ba3857b079877ee1e2043ecc96a65bd79b07ea83e21d2b8378ee72f29edfe23a46fc95c22cd0e58662b9bd7279f512d0d6e6ab6776181fa000b218c83707b6cd0860613dcac2dd2fa227c787a3ef556378750545afd7f5568427451eae0f49610828694567ad9d2ee62154048c52c6a8ec5043bd3b7e1cc6a4298b812d20a30fbdfdaba293382842a66bb9517c11dc4fb7ea2060fc8aefb5c18c62cff63fbf84bd9dafabbce28a7b861f64e5ec0ba4abc6d50c5c43b6f2b66ac32d309b142ebfbd51e5d27ab7efc25da352f0a8329358733e0b6b733b4be20c1518e044dc8682aab75dd20e012caacb040f525a7e406daae87b7fa74ddc5b0
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20131106-sip.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70914);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/04/04");

  script_cve_id("CVE-2013-5553");
  script_bugtraq_id(63553);
  script_osvdb_id(99491);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc42558");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug25383");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20131106-sip");

  script_name(english:"Cisco IOS Software Session Initiation Protocol Denial of Service Vulnerability (cisco-sa-20131106-sip)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the Session Initiation Protocol (SIP)
implementation in Cisco IOS Software that could allow an
unauthenticated, remote attacker to cause a reload of an affected
device or cause memory leaks that may result in system
instabilities. To exploit this vulnerability, affected devices must
be configured to process SIP messages. Limited Cisco IOS Software
releases are affected.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20131106-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?949a0108");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20131106-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/14");

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
report = "";
cbi = "CSCuc42558 and CSCug25383";
fixed_ver = "";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( ver == '15.1(4)GC' ) flag++;
if ( ver == '15.1(4)GC1' ) flag++;
if ( ver == '15.1(4)M4' ) flag++;
if ( ver == '15.1(4)M5' ) flag++;
if ( ver == '15.1(4)M6' ) flag++;
if ( ver == '15.1(4)XB8' ) flag++;
if ( ver == '15.1(4)XB8a' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
    if (check_cisco_result(buf))
    {
      if (
           (preg(multiline:TRUE, pattern:"CCSIP_UDP_SOCKET", string:buf)) ||
           (preg(multiline:TRUE, pattern:"CCSIP_TCP_SOCKET", string:buf))
         ) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : ' + cbi +
    '\n    Installed release : ' + ver + '\n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
