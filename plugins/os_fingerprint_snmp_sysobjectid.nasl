#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44344);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2017/04/25 14:31:38 $");

  script_name(english:"OS Identification : SNMP sysObjectID");
  script_summary(english:"Identifies devices based on SNMP sysObjectID.");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to identify the remote operating system based on an
SNMP query of its sysObjectID object.");
  script_set_attribute(attribute:"description", value:
"The remote operating system can be identified by querying its
sysObjectID object using SNMP.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_dependencies("snmp_sysDesc.nasl");
  script_require_keys("SNMP/OID");

  exit(0);
}

oid = get_kb_item("SNMP/OID");
if (!oid) exit(0, "The 'SNMP/OID' KB item is missing.");

i = 0;
name = make_array();
oid_pat  = make_array();
dev_type  = make_array();

name[i] = "Avaya IP Phone";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.6889\.1\.69\.(1\.(1|2|6|7)|2\.3)$";
dev_type[i] = "embedded";
i++;

name[i] = "Brocade Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.1588\.2\.1\.1\.1$";
dev_type[i] = "switch";
i++;

name[i] = "HP JetDirect";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.11\.2\.3\.9\.1$";
dev_type[i] = "printer";
i++;

name[i] = "HP plotter";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.11\.2\.3\.9\.2$";
dev_type[i] = "printer";
i++;

name[i] = "HP LaserJet";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.11\.2\.3\.9\.4$";
dev_type[i] = "printer";
i++;

name[i] = "KYOCERA Printer";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.1347\.41$";
dev_type[i] = "printer";
i++;

name[i] = "3Com LinkSwitch 1000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.13$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 500 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.14$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 2700AU Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.15$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 2700 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.16$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 2700TLiAU Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.18$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 2700TLi Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.19$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 3000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.22$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Superstack 9000 SX Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.32$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack3 4300 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.38$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 3870 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.43$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 3870 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.44$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2226 Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.57$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2250 Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.58$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2426 PWR Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.59$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2916-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.60$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2924-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.61$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2948-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.62$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2924-PWR Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.63$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2920-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.71$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2928-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.72$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2952-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.73$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2928-PWR Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.74$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2928-HPWR Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.75$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2226 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.76$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline 2250-SFP Plus Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.77$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Baseline S2426 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.8\.78$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 9000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.9\.13\.1\.2\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 9000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.9\.13\.3\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 3500 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.1\.1\.1\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Superstack 3900 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.2\.2\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack II Switch 3900-24 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.2\.2\.1\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack II Switch 3900-36 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.2\.2\.1\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Superstack 9300 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.2\.2\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 9300 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.2\.2\.2\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com 6080 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.2\.26$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8807 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.4$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8810 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.5$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8814 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.6$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500G-EI Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.7$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500G 48-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.8$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-SI 28-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.11$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-52-SI Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.12$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-28-EI Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.13$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-EI 52-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.14$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-EI PWR 28-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.15$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-52-PWR-EI Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.16$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500-28-FX-EI Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.17$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 5500G-EI 24-Port-SFP Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.18$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7754 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.19$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7757 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.20$";
dev_type[i] = "switch";
i++;

name[i] = "3Com 4500 26-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.21$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500 50-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.22$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500-26-PWR Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.23$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500-50-PWR Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.24$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch witch 7758 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.25$";
dev_type[i] = "switch";
i++;

name[i] = "3Com 4200G 12-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.27$";
dev_type[i] = "switch";
i++;

name[i] = "3Com 4200G 24-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.28$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4200G-48 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.29$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500G 24-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.30$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500G-48 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.31$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500G-24-PWR Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.32$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4500G-48-PWR Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.33$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4800G 24-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.34$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4800G 48-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.35$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4800G PWR 24-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.36$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4800G PWR 48-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.37$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4800G 24-Port-SFP Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.38$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8807-V5 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.39$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8810-V5 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.40$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 8814-V5 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.41$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 9-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.42$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 18-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.43$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 26-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.44$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 52-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.45$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 9-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.46$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 18-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.47$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 26-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.48$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4200G-24-PWR Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.49$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7902E Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.50$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7903E Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.51$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7906E Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.52$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7906EV Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.53$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7910E Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.54$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 7903E-S Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.74$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 26-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.77$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4210 PWR 26-Port Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.80$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4510G-24 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.83$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 4510G-48 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.1\.16\.4\.3\.84$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 1100 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Switch 40x0 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.10$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 4200 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.11$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 3300 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 4400 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.4$";
dev_type[i] = "switch";
i++;

name[i] = "3Com SuperStack 4900 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.43\.10\.27\.4\.1\.2\.5$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 3500 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.2\.1\.1\.1\.1\.9$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 6000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 6012 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.2\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 6004 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.2\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LANplex 2000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.3$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 2500 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.3\.1$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LANplex 2200 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.3\.2$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LANplex 2000 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.3\.3$";
dev_type[i] = "switch";
i++;

name[i] = "3Com LinkSwitch 2200 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.1\.3\.3\.4\.7$";
dev_type[i] = "switch";
i++;

name[i] = "3Com Corebuilder 3500 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.114\.2\.1\.1\.1\.1\.9$";
dev_type[i] = "switch";
i++;

name[i] = "FortiGate-ONE";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-100";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.1000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1000";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1000A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1000AFA2";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10002$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1000ALENC";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1000C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.10004$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-100A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.1001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-110C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.1002$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-111C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.1003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-100D";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.1004$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-1240B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.12400$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-VM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.20$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-200";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.2000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-200A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.2001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-224B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.2002$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-200B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.2003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-200BPOE";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.2004$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-20C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.210$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-20C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.212$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-20CA";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.213$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-20CA";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.214$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-VM64";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.30$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-300";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3000";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.30000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-300A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-310B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3002$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-300D";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-311B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3004$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-300C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.3005$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3016B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.30160$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-30B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.302$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3040B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.30400$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3140B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.30401$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-30B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.310$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-3600";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.36000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3600A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.36003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3810A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.38100$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3950B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.39500$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-3951B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.39501$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-400";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.4000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-400A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.4001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-40C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.410$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-40C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.411$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-50A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.500$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-500";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.5000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-5002FB2";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-500A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.5001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-5001";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50010$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-5001A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50011$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-5001FA2";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50012$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-5001B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50013$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiSwitch-5203B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50023$";
dev_type[i] = "switch";
i++;

name[i] = "FortiGate-5005FA2";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.50051$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-50B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.502$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-51B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.504$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-50B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.510$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-5101C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.51010$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-60";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.600$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-600C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.6003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-60M";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.601$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-60ADSL";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.602$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-60B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.603$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-60";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.610$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-60A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.611$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-60AM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.612$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-60B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.613$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-60C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.615$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-60C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.616$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-60CM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.617$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-60CA";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.618$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-6XMB";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.619$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiGate-620B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.6200$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-600D";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.6201$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-60CP";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.621$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-621B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.6210$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-80C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.800$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-800";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.8000$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-800F";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.8001$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-800C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.8003$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-80CM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.801$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiGate-82C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.802$";
dev_type[i] = "firewall";
i++;

name[i] = "FortiWifi-80CM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.810$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiWifi-81CM";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.101\.1\.811$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "FortiAnalyzer-100";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.1000$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-1000B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.10002$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-100A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.1001$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-100B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.1002$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-100C";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.1003$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-2000";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.20000$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-2000A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.20001$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-400";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.4000$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-4000";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.40000$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-4000A";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.40001$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-400B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.4002$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-800";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.8000$";
dev_type[i] = "embedded";
i++;

name[i] = "FortiAnalyzer-800B";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.12356\.102\.1\.8002$";
dev_type[i] = "embedded";
i++;

name[i] = "Nortel BayStack 100";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.26\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel 28200 Ethernet Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.28\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 302";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.29\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 350";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.30\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 350-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.30\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 150";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.31\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 303-304";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.32\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 303-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.32\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 200";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.33\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 250";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.34\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 450-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.35\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 410-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.36\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack Integrated Communication Server";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.37\.1$";
dev_type[i] = "embedded";
i++;

name[i] = "Nortel Accelar 8132";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.38\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 8148";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.38\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 670";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.39\.1$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "Nortel BPS 2000-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.40\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 3580-16F";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.41\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel BayStack 10 Power Supply Unit";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.42\.1$";
dev_type[i] = "embedded";
i++;

name[i] = "Nortel Ethernet Routing Switch 420-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.43\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel OPTera Metro 1200 Ethernet Service Module";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.44\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 380-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.45\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 470-48T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.46\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel OPTera Metro 1450 Ethernet Service Module";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.47\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel OPTera Metro 1400 Ethernet Service Module";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.48\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 460-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.49\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel OPTera Metro 8000";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.50\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 380-24F";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.51\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5510-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.52\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5510-48T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.53\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 470-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.54\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Access Point 2220";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.55\.1$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "Nortel WLANS ecurity Switch 2250";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.56\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 425-48T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.57\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 425-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.57\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Access Point 2221";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.58\.1$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "Nortel Ethernet Routing Switch 5520-24T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.59\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5520-48T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.59\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2270";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.60\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 325-24T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.61\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 325-24G";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.61\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Access Point 2225";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.62\.1$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "Nortel Ethernet Routing Switch 470-24T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.63\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 470-48T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.64\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2350";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2360";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2361";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.3$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2370";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.4$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel WLAN Security Switch 2380";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.5$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel MX-2800";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.67\.8$";
dev_type[i] = "wireless-access-point";
i++;

name[i] = "Nortel Ethernet Routing Switch 4548GT";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4548GT-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4550T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.3$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4550T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.4$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4526FX";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.5$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4526GTX-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.6$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4526GTX";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.7$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4524GT";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.8$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4526T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.9$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4526T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.10$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 4524GT-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.71\.11$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 2500-26T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.72\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 2500-26T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.72\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 2500-50T";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.72\.3$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 2500-50T-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.72\.4$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5698-TFD-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.74\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5698-TFD";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.74\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5650-TD-PWR";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.74\.3$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5650-TD";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.74\.4$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 5632-FD";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.74\.5$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 6628-XSGT";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.76\.1$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch 6632-XTS";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.45\.3\.76\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Samsung SCX Series Printer";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.236\.11\.5\.1$";
dev_type[i] = "printer";
i++;

name[i] = "Nortel Internet Telephony Gateway";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.562\.3\.11\.2$";
dev_type[i] = "embedded";
i++;

name[i] = "Nortel VGMC";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.562\.3\.11\.5$";
dev_type[i] = "embedded";
i++;

name[i] = "Lantronix Universal Device Server UDS1100";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.1723\.2\.1\.3$";
dev_type[i] = "embedded";
i++;

name[i] = "Nortel Accelar 1100 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.2$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 1250 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.6$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 1150 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.7$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 1200 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.8$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 1050 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.9$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 740 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.20$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 750 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.21$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 790 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.22$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Accelar 750S Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.23$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel 8003 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.280887555$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel 8006 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.280887558$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel 8010 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.280887562$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel 8010co Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.1623064842$";
dev_type[i] = "switch";
i++;

# nb: ERS => "Ethernet Routing Switch"
name[i] = "Nortel ERS 8610 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.30$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel ERS 8606 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.31$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8110 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.32$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8106 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.33$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8603 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.34$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8103 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.35$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8110co Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.36$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8610co Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.37$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Ethernet Routing Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.40$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 1424 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.42$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 1648 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.43$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 1612 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.44$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 1624 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.45$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel Passport 8310 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.47$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel ERS 8306 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.48$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel ERS 8010 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.49$";
dev_type[i] = "switch";
i++;

name[i] = "Nortel ERS 8006 Switch";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.2272\.50$";
dev_type[i] = "switch";
i++;

name[i] = "Silver Peak Systems";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.23867\.1\.2\.3(1|8)$";
dev_type[i] = "embedded";
i++;

name[i] = "VBrick";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.4289\.1\.2\.1\.2$";
dev_type[i] = "embedded";
i++;

name[i] = "Wiesemann & Theis Com-Server";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.5040\.1\.1\.1$";
dev_type[i] = "embedded";
i++;

name[i] = "Wiesemann & Theis Web-Thermograph";
oid_pat[i]  = "^1\.3\.6\.1\.4\.1\.5040\.1\.2\.(1|2|3|6|8|9|16)$";
dev_type[i] = "embedded";
i++;

n = i;
for (i=0; i<n; i++)
{
  if (ereg(pattern:oid_pat[i], string:oid))
  {
    set_kb_item(name:"Host/OS/sysObjectID", value:name[i]);
    set_kb_item(name:"Host/OS/sysObjectID/Confidence", value:100);
    set_kb_item(name:"Host/OS/sysObjectID/Type", value:dev_type[i]);
    exit(0);
  }
}
