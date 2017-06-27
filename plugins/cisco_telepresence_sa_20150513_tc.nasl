#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83731);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2014-2174", "CVE-2015-0722");
  script_bugtraq_id(74636, 74639);
  script_osvdb_id(122095, 122096);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj68952");
  script_xref(name:"IAVA", value:"2015-A-0117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub67651");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150513-tc");

  script_name(english:"Cisco TelePresence TC and TE Software Multiple Vulnerabilities (cisco-sa-20150513-tc)");
  script_summary(english:"Checks the software version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco TelePresence TC or TE software running on the
remote device is affected by one or more of the following
vulnerabilities :

  - A implementation flaw exists in the authentication and
    authorization controls for internal services. An
    unauthenticated attacker, within the broadcast or
    collision domains, or who has physical access to the
    device, can exploit this flaw to bypass authentication
    and obtain root access to the system by connecting to
    the affected service. (CVE-2014-2174)

  - A flaw exists due to insufficient implementation of
    flood controls in the network drivers. A remote,
    unauthenticated attacker, by rapidly sending crafted
    IP packets to the device, can exploit this to cause
    processes to restart, potentially leading to a reload
    of the affected system and a denial of service.
    (CVE-2015-0722)");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150513-tc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?462644eb");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38719");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38718");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Cisco TelePresence TC or TE software version
referenced in Cisco Security Advisory cisco-sa-20150513-tc.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_tc_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:telepresence_te_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_telepresence_mcu_detect.nasl");
  script_require_keys("Cisco/TelePresence_MCU/Device", "Cisco/TelePresence_MCU/Version");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "Cisco TelePresence TC or TE software";
device   = get_kb_item_or_exit("Cisco/TelePresence_MCU/Device");
version  = get_kb_item_or_exit("Cisco/TelePresence_MCU/Version");

match = eregmatch(pattern: "^(T[CE])(\d+(?:\.\d+)*)", string:version);
if (isnull(match)) audit(AUDIT_UNKNOWN_APP_VER, app_name);

app_name = "Cisco TelePresence " + match[1];
ver = match[2];
fix = "7.3.2"; # 7.3.2 addresses both issues

# T Series device have no fix available
if (device =~ " T1($|[ \n\r])" || device =~ " T3($|[ \n\r])")
  fix = "See vendor advisory.";
else if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, app_name, ver);

port = 0;
if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
