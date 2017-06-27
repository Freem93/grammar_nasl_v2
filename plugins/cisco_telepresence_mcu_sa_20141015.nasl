#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78624);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/05/24 04:37:33 $");

  script_cve_id("CVE-2014-3397");
  script_bugtraq_id(70591);
  script_osvdb_id(113380);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtz35468");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20141015-mcu");

  script_name(english:"Cisco TelePresence MCU Software Memory Exhaustion");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a flaw that can allow a denial of
service via memory exhaustion.");
  script_set_attribute(attribute:"description", value:
"According to the self-reported version, returned by either the SNMP or
FTP service running on the remote device, the Cisco TelePresence MCU
software is affected by a vulnerability that can allow a remote,
unauthenticated attacker to cause a denial of service via memory
exhaustion.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20141015-mcu
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d8abd8d8");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCtz35468");

  script_set_attribute(attribute:"solution", value:"Upgrade to the appropriate software version per the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4203");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4205");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4210");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4215");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4220");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4505");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4510");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4515");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_4520");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:telepresence_mcu_mse_8420");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_mse_series_software:4.3%282.18%29");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_mcu_4500_series_software:4.3%282.18%29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Version", "Cisco/TelePresence_MCU/Device");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

device   = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version  = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");
fullname = "Cisco TelePresence "+device;

if (
  device !~ "MCU 4[25]\d\d" &&
  "MSE 8420" >!< device
)
audit(AUDIT_DEVICE_NOT_VULN,fullname);

vulnvers = make_list(
  "4.1(1.51)",
  "4.1(1.59)",
  "4.2(1.43)",
  "4.2(1.46)",
  "4.2(1.50)",
  "4.3(1.68)",
  "4.3(2.18)"
);

vuln = FALSE;
foreach vulnver (vulnvers)
{
  if (version == vulnver)
  {
     vuln = TRUE;
     break;
  }
}

if (!vuln) audit(AUDIT_DEVICE_NOT_VULN, fullname, version);

if (report_verbosity > 0)
{
  report = '\n  Installed version : ' + version +
           '\n  Fixed version     : 4.3(2.30)' +
           '\n';
  security_hole(port:0, extra:report);
}
else security_hole(0);
