#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73915);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/11 04:29:34 $");

  script_cve_id(
    "CVE-2014-2156",
    "CVE-2014-2157",
    "CVE-2014-2158",
    "CVE-2014-2159",
    "CVE-2014-2160",
    "CVE-2014-2161"
  );
  script_bugtraq_id(67166, 67167);
  script_osvdb_id(106449, 106450, 106451, 106452, 106453, 106454);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty45739");
  script_xref(name:"IAVA", value:"2014-A-0067");
  script_xref(name:"CISCO-BUG-ID", value:"CSCty45733");
  script_xref(name:"CISCO-BUG-ID", value:"CSCty45720");
  script_xref(name:"CISCO-BUG-ID", value:"CSCtq78722");
  script_xref(name:"CISCO-BUG-ID", value:"CSCty45745");
  script_xref(name:"CISCO-BUG-ID", value:"CSCty45731");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140430-mxp");

  script_name(english:"Cisco TelePresence MXP Series Software Multiple Vulnerabilities (cisco-sa-20140430-mxp)");
  script_summary(english:"Checks software version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco TelePresence MXP Series software running on the
remote host is affected by one or more of the following issues :

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2156 / CSCty45739)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2157 / CSCty45733)

  - A denial of service vulnerability exists due to a flaw
    in the SIP implementation, potentially allowing a remote
    attacker to cause a device reload by sending crafted SIP
    packets. (CVE-2014-2158 / CSCty45720)

  - A denial of service vulnerability exists due to a flaw
    in the H.225 subsystem, potentially allowing a remote
    attacker to cause a device reload by sending crafted
    packets. (CVE-2014-2159 / CSCtq78722)

  - A denial of service vulnerability exists due to a flaw
    in the H.225 subsystem, potentially allowing a remote
    attacker to cause a device reload by sending crafted
    packets. (CVE-2014-2160 / CSCty45745)

  - A denial of service vulnerability exists due to a flaw
    in the H.225 subsystem, potentially allowing a remote
    attacker to cause a device reload by sending crafted
    packets. (CVE-2014-2161 / CSCty45731)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140430-mxp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c43f3837");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Cisco TelePresence MXP series software version
referenced in Cisco Security Advisory cisco-sa-20140430-mxp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/08");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_system_software");
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

app_name = "Cisco TelePresence System MXP Series Software";
device = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

if (
  device !~ " 6000MXP($|[ \n\r])" && device !~ " 3000MXP($|[ \n\r])" &&
  device !~ " 2000MXP($|[ \n\r])" && device !~ " 1700MXP($|[ \n\r])" &&
  device !~ " 1000MXP($|[ \n\r])" && device !~ " 990MXP($|[ \n\r])"  &&
  device !~ " 880MXP($|[ \n\r])"  && device !~ " 770MXP($|[ \n\r])"  &&
  device !~ " 550MXP($|[ \n\r])"  && device !~ " Edge 75MXP($|[ \n\r])" &&
  device !~ " Edge 85MXP($|[ \n\r])" && device !~ " Edge 95MXP($|[ \n\r])"
) audit(AUDIT_HOST_NOT, "an affected Cisco TelePresence device");

match = eregmatch(pattern: "^F(\d+(?:\.\d+)*)", string:version);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, app_name);
fix = "9.3.1";

if (ver_compare(ver:match[1], fix:fix, strict:FALSE) == -1)
{
  port = 0;
  if (report_verbosity > 0)
  {
    report = '\n  Detected version : ' + version +
             '\n  Fixed version    : F' + fix +
             '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app_name, version);
