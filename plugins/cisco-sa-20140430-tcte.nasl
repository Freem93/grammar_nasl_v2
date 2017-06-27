#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73916);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/11 04:29:34 $");

  script_cve_id(
    "CVE-2014-2162",
    "CVE-2014-2163",
    "CVE-2014-2164",
    "CVE-2014-2165",
    "CVE-2014-2166",
    "CVE-2014-2167",
    "CVE-2014-2168",
    "CVE-2014-2169",
    "CVE-2014-2170",
    "CVE-2014-2171",
    "CVE-2014-2172",
    "CVE-2014-2173",
    "CVE-2014-2175"
  );
  script_bugtraq_id(67170);
  script_osvdb_id(
    106455,
    106456,
    106457,
    106458,
    106459,
    106460,
    106461,
    106462,
    106463,
    106464,
    106465,
    106466,
    106467
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCto70562");
  script_xref(name:"IAVA", value:"2014-A-0067");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq72699");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq78849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCty44804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua6496");
  script_xref(name:"CISCO-BUG-ID", value:"CSCua86589");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub67692");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub67693");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud29566");
  script_xref(name:"CISCO-BUG-ID", value:"CSCud81796");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue60202");
  script_xref(name:"CISCO-BUG-ID", value:"CSCue60211");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj94651");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140430-tcte");

  script_name(english:"Cisco TelePresence TC and TE Software Multiple Vulnerabilities (cisco-sa-20140430-tcte)");
  script_summary(english:"Checks software version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco TelePresence TC or TE software running on the
remote host is affected by one or more of the following issues :

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2162 / CSCud29566)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2163 / CSCua64961)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2164 / CSCuj94651)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2165 / CSCtq72699)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2166 / CSCto70562)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2167 / CSCua86589)

  - A remote code execution vulnerability exists due to a
    buffer overflow in Cisco TelePresence TC and TE
    software, potentially allowing a remote attacker to
    execute arbitrary code by sending crafted DNS response
    packets. (CVE-2014-2168 / CSCty44804)

  - A remote command execution vulnerability exists due to
    a failure to sanitize user-supplied input to internal
    scripts, potentially allowing an authenticated attacker
    to execute arbitrary commands. (CVE-2014-2169 /
    CSCue60211)

  - A remote command execution vulnerability exists due to
    a failure to sanitize user-supplied input to tshell
    scripts, potentially allowing an authenticated attacker
    to execute arbitrary commands. (CVE-2014-2170 /
    CSCue60202)

  - A remote code execution vulnerability exists that
    potentially allows remote attackers to execute arbitrary
    code via crafted SIP packets. (CVE-2014-2171 /
    CSCud81796)

  - A privilege escalation vulnerability exists due to a
    buffer overflow in Cisco TelePresence TC and TE
    software, potentially allowing local attackers to gain
    privileges. (CVE-2014-2172 / CSCub67693)

  - A privilege escalation vulnerability exists due to
    improperly restricting access to the serial port,
    potentially allowing local attackers to gain privileges
    via unspecified commands. (CVE-2014-2173 / CSCub67692)

  - A denial of service vulnerability exists that
    potentially allows remote attackers to trigger memory
    consumption via crafted H.225 packets.
    (CVE-2014-2175 / CSCtq78849)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140430-tcte
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6abd1d7e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Cisco TelePresence TC or TE software version
referenced in Cisco Security Advisory cisco-sa-20140430-tcte.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_te_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence TC or TE software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

if (
  # Devices running 4.1.x apparently don't report a device type.
  !((device == "unknown" && report_paranoia > 1) ||
  # profile series
  "TelePresence Profile" >< device ||
  # T Series
  device =~ " T1($|[ \n\r])" || device =~ " T3($|[ \n\r])" ||
  # Quick Set series (this covers VX clinical assistant as well, which
  # is an SX20)
  device =~ " SX20($|[ \n\r])" || device =~ " C20($|[ \n\r])" ||
  # C series
  device =~ " C40($|[ \n\r])" || device =~ " C60($|[ \n\r])" || device =~ " C90($|[ \n\r])" ||
  # MX Series
  device =~ " MX200($|[ \n\r])" || device =~ " MX300($|[ \n\r])" ||
  # EX Series
  device =~ " EX60($|[ \n\r])" || device =~ " EX90($|[ \n\r])")
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

match = eregmatch(pattern: "^T[CE](\d+(?:\.\d+)*)", string:version);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

if (match[1] =~ "^[456]\.") fix = "6.3.1";
else if (match[1] =~ "^7\.") fix = "7.1.1";
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);

if (ver_compare(ver:match[1], fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report = '\n  Detected version : ' + version +
             '\n  Fixed version    : TC' + fix +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
