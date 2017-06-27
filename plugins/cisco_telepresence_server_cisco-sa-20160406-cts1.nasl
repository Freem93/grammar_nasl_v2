#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90540);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:15:08 $");

  script_cve_id("CVE-2015-6313");
  script_osvdb_id(136734);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuv47565");
  script_xref(name:"IAVA", value:"2016-A-0094");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160406-cts1");

  script_name(english:"Cisco TelePresence Server HTTP Parsing Engine DoS (cisco-sa-20160406-cts1)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco TelePresence Server
running on the remote host is affected by a denial of service
vulnerability in the HTTP parsing engine due to improper handling of
specially crafted URLs. An unauthenticated, remote attacker can
exploit this, via multiple URL requests, to exhaust memory resources,
resulting in a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160406-cts1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4b93acb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuv47565");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuv47565.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_server_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_7010");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_mse_8710");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_310");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_320");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_multiparty_media_820");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_server_on_virtual_machine");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_server_detect.nasl");
  script_require_keys("Cisco/TelePresence_Server/Version", "Cisco/TelePresence_Server/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

model    = get_kb_item_or_exit("Cisco/TelePresence_Server/Model");
version  = get_kb_item_or_exit("Cisco/TelePresence_Server/Version");

if (
  model =~ "^7010([^0-9]|$)" ||
  model =~ "^8710([^0-9]|$)" ||
  model =~ "^310([^0-9]|$)"  ||
  model =~ "^320([^0-9]|$)"  ||
  "Virtual Machine" >< model
) fix = '4.2(4.18)';
else if (
  model =~ "^820([^0-9]|$)"
) fix = '4.2(3.72)';
else
  audit(AUDIT_HOST_NOT, "a Cisco TelePresence 7010/8710/310/320/820/VM");

# Affects 4.1(2.29) through 4.2(4.17), excluding 820 which is to 4.2(3.72)
if (
  (cisco_gen_ver_compare(a:version, b:'4.1(2.29)') >= 0) &&
  (cisco_gen_ver_compare(a:version, b:fix) < 0)
)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : ' + fix +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco TelePresence Server software", version);
