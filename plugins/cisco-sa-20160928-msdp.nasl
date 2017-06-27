#TRUSTED 5aee199aa800bc3945a33e67976e0834657cdcd28d313deee059bf3219d1467cd664ca90b20dbe7ca6f2bd1ee561be2a47ca54dc1e7a32c1305528931b6b054cd65d66ffb194259969ab79137d6c87383e65df518d4767ffe86b740e5b4305ebacf35e0aba8897aaf7b43ad6931d9942e61bf5724aa111dc6f35c8c2bcaced0ff5e2a5623b99d0889fb4bc9bd98a8bbea2baa5be28572777bd14b9c52e94f746ab4ee64c86eac84b09fca7f5e0dbc233e4ea17443819a0035d3ad156fef74486b3b902acf6136871538979ea77e2acf3f38ef96b4b3a227b2d8073e7bf116e69879ceab0a639b8833614552c05f8001451b5469e92303c4d8775bce05cab73d73ab65613c778d6099a9d1005f67b69ca31eabdfbf007896b0c17734bd4ecfa36ecba93216660d0b8b35a2d9975b17e49a2a53082684ea2b717310ac8c149e5d9314f2b5935e2d1d3b5e8744f9c759be74d9e526ab43b6cbc344cb4b9da48a9063ef69b7c00234eb0d131ab69bc8ac63c9c116f924c0fa73ac5c666230147208f577255955e7f8ae1bfff92258d05e49399bad21c83b2f2a67cda15b78c63c585a8f99a881264bd6c79965c82a82f70756dceebf1e6640880fe7d3bec00ee4d5a3c987d404363a5981b54da5af4c97faf4a5e0482a4435c843cd304f9f3cb70d6babd8be00397ad20bb9411a3ace5264f191857343e85fa5f70fe55512f49b4f6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93899);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/24");

  script_cve_id("CVE-2016-6382", "CVE-2016-6392");
  script_bugtraq_id(93211);
  script_osvdb_id(144899, 144900);
  script_xref(name:"CISCO-BUG-ID", value:"CSCud36767");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuy16399");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160928-msdp");

  script_name(english:"Cisco IOS Multicast Routing Multiple DoS (cisco-sa-20160928-msdp)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Cisco IOS device is affected by multiple denial of service
vulnerabilities :

  - A denial of service vulnerability exists due to improper
    validation of packets encapsulated in a PIM register
    message. An unauthenticated, remote attacker can exploit
    this, by sending an IPv6 PIM register packet to a PIM
    rendezvous point (RP), to cause the device to restart.
    (CVE-2016-6382)

  - A denial of service vulnerability exists in the IPv4
    Multicast Source Discovery Protocol (MSDP)
    implementation due to improper validation of
    Source-Active (SA) messages received from a configured
    MSDP peer. An unauthenticated, remote attacker can
    exploit this to cause the device to restart.
    (CVE-2016-6392)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160928-msdp
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCud36767");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuy16399");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20160928-msdp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;
override = 0;

if (version == "12.2(33)CX") flag = 1;
else if (version == "12.2(33)CY") flag = 1;
else if (version == "12.2(33)CY1") flag = 1;
else if (version == "12.2(58)EX") flag = 1;
else if (version == "12.2(58)EY") flag = 1;
else if (version == "12.2(58)EY1") flag = 1;
else if (version == "12.2(58)EY2") flag = 1;
else if (version == "12.2(58)EZ") flag = 1;
else if (version == "12.2(60)EZ") flag = 1;
else if (version == "12.2(60)EZ1") flag = 1;
else if (version == "12.2(60)EZ2") flag = 1;
else if (version == "12.2(60)EZ3") flag = 1;
else if (version == "12.2(60)EZ4") flag = 1;
else if (version == "12.2(60)EZ5") flag = 1;
else if (version == "12.2(60)EZ6") flag = 1;
else if (version == "12.2(60)EZ7") flag = 1;
else if (version == "12.2(60)EZ8") flag = 1;
else if (version == "12.2(60)EZ9") flag = 1;
else if (version == "12.2(33)IRA") flag = 1;
else if (version == "12.2(33)IRB") flag = 1;
else if (version == "12.2(33)IRC") flag = 1;
else if (version == "12.2(33)IRD") flag = 1;
else if (version == "12.2(33)IRE") flag = 1;
else if (version == "12.2(33)IRE1") flag = 1;
else if (version == "12.2(33)IRE2") flag = 1;
else if (version == "12.2(33)IRF") flag = 1;
else if (version == "12.2(33)IRG") flag = 1;
else if (version == "12.2(33)IRG1") flag = 1;
else if (version == "12.2(33)IRH") flag = 1;
else if (version == "12.2(33)IRH1") flag = 1;
else if (version == "12.2(33)IRI") flag = 1;
else if (version == "12.2(33)MRA") flag = 1;
else if (version == "12.2(33)MRB") flag = 1;
else if (version == "12.2(33)MRB1") flag = 1;
else if (version == "12.2(33)MRB2") flag = 1;
else if (version == "12.2(33)MRB3") flag = 1;
else if (version == "12.2(33)MRB4") flag = 1;
else if (version == "12.2(33)MRB5") flag = 1;
else if (version == "12.2(33)MRB6") flag = 1;
else if (version == "12.2(33)SB") flag = 1;
else if (version == "12.2(33)SB1") flag = 1;
else if (version == "12.2(33)SB1a") flag = 1;
else if (version == "12.2(33)SB1b") flag = 1;
else if (version == "12.2(33)SB10") flag = 1;
else if (version == "12.2(33)SB11") flag = 1;
else if (version == "12.2(33)SB12") flag = 1;
else if (version == "12.2(33)SB13") flag = 1;
else if (version == "12.2(33)SB14") flag = 1;
else if (version == "12.2(33)SB15") flag = 1;
else if (version == "12.2(33)SB16") flag = 1;
else if (version == "12.2(33)SB17") flag = 1;
else if (version == "12.2(33)SB2") flag = 1;
else if (version == "12.2(33)SB3") flag = 1;
else if (version == "12.2(33)SB4") flag = 1;
else if (version == "12.2(33)SB5") flag = 1;
else if (version == "12.2(33)SB6") flag = 1;
else if (version == "12.2(33)SB6a") flag = 1;
else if (version == "12.2(33)SB6b") flag = 1;
else if (version == "12.2(33)SB7") flag = 1;
else if (version == "12.2(33)SB8") flag = 1;
else if (version == "12.2(33)SB8b") flag = 1;
else if (version == "12.2(33)SB8c") flag = 1;
else if (version == "12.2(33)SB8d") flag = 1;
else if (version == "12.2(33)SB8e") flag = 1;
else if (version == "12.2(33)SB8f") flag = 1;
else if (version == "12.2(33)SB8g") flag = 1;
else if (version == "12.2(33)SB9") flag = 1;
else if (version == "12.2(33)SCA") flag = 1;
else if (version == "12.2(33)SCA1") flag = 1;
else if (version == "12.2(33)SCA2") flag = 1;
else if (version == "12.2(33)SCB") flag = 1;
else if (version == "12.2(33)SCB1") flag = 1;
else if (version == "12.2(33)SCB10") flag = 1;
else if (version == "12.2(33)SCB11") flag = 1;
else if (version == "12.2(33)SCB2") flag = 1;
else if (version == "12.2(33)SCB3") flag = 1;
else if (version == "12.2(33)SCB4") flag = 1;
else if (version == "12.2(33)SCB5") flag = 1;
else if (version == "12.2(33)SCB6") flag = 1;
else if (version == "12.2(33)SCB7") flag = 1;
else if (version == "12.2(33)SCB8") flag = 1;
else if (version == "12.2(33)SCB9") flag = 1;
else if (version == "12.2(33)SCC") flag = 1;
else if (version == "12.2(33)SCC1") flag = 1;
else if (version == "12.2(33)SCC2") flag = 1;
else if (version == "12.2(33)SCC3") flag = 1;
else if (version == "12.2(33)SCC4") flag = 1;
else if (version == "12.2(33)SCC5") flag = 1;
else if (version == "12.2(33)SCC6") flag = 1;
else if (version == "12.2(33)SCC7") flag = 1;
else if (version == "12.2(33)SCD") flag = 1;
else if (version == "12.2(33)SCD1") flag = 1;
else if (version == "12.2(33)SCD2") flag = 1;
else if (version == "12.2(33)SCD3") flag = 1;
else if (version == "12.2(33)SCD4") flag = 1;
else if (version == "12.2(33)SCD5") flag = 1;
else if (version == "12.2(33)SCD6") flag = 1;
else if (version == "12.2(33)SCD7") flag = 1;
else if (version == "12.2(33)SCD8") flag = 1;
else if (version == "12.2(33)SCE") flag = 1;
else if (version == "12.2(33)SCE1") flag = 1;
else if (version == "12.2(33)SCE2") flag = 1;
else if (version == "12.2(33)SCE3") flag = 1;
else if (version == "12.2(33)SCE4") flag = 1;
else if (version == "12.2(33)SCE5") flag = 1;
else if (version == "12.2(33)SCE6") flag = 1;
else if (version == "12.2(33)SCF") flag = 1;
else if (version == "12.2(33)SCF1") flag = 1;
else if (version == "12.2(33)SCF2") flag = 1;
else if (version == "12.2(33)SCF3") flag = 1;
else if (version == "12.2(33)SCF4") flag = 1;
else if (version == "12.2(33)SCF5") flag = 1;
else if (version == "12.2(33)SCG") flag = 1;
else if (version == "12.2(33)SCG1") flag = 1;
else if (version == "12.2(33)SCG2") flag = 1;
else if (version == "12.2(33)SCG3") flag = 1;
else if (version == "12.2(33)SCG4") flag = 1;
else if (version == "12.2(33)SCG5") flag = 1;
else if (version == "12.2(33)SCG6") flag = 1;
else if (version == "12.2(33)SCG7") flag = 1;
else if (version == "12.2(33)SCH") flag = 1;
else if (version == "12.2(33)SCH0a") flag = 1;
else if (version == "12.2(33)SCH1") flag = 1;
else if (version == "12.2(33)SCH2") flag = 1;
else if (version == "12.2(33)SCH2a") flag = 1;
else if (version == "12.2(33)SCH3") flag = 1;
else if (version == "12.2(33)SCH4") flag = 1;
else if (version == "12.2(33)SCH5") flag = 1;
else if (version == "12.2(33)SCH6") flag = 1;
else if (version == "12.2(33)SCI") flag = 1;
else if (version == "12.2(33)SCI1") flag = 1;
else if (version == "12.2(33)SCI1a") flag = 1;
else if (version == "12.2(33)SCI2") flag = 1;
else if (version == "12.2(33)SCI2a") flag = 1;
else if (version == "12.2(33)SCI3") flag = 1;
else if (version == "12.2(33)SCJ") flag = 1;
else if (version == "12.2(58)SE") flag = 1;
else if (version == "12.2(58)SE1") flag = 1;
else if (version == "12.2(58)SE2") flag = 1;
else if (version == "12.2(33)SRB") flag = 1;
else if (version == "12.2(33)SRB1") flag = 1;
else if (version == "12.2(33)SRB2") flag = 1;
else if (version == "12.2(33)SRB3") flag = 1;
else if (version == "12.2(33)SRB4") flag = 1;
else if (version == "12.2(33)SRB5") flag = 1;
else if (version == "12.2(33)SRB5a") flag = 1;
else if (version == "12.2(33)SRB6") flag = 1;
else if (version == "12.2(33)SRB7") flag = 1;
else if (version == "12.2(33)SRC") flag = 1;
else if (version == "12.2(33)SRC1") flag = 1;
else if (version == "12.2(33)SRC2") flag = 1;
else if (version == "12.2(33)SRC3") flag = 1;
else if (version == "12.2(33)SRC4") flag = 1;
else if (version == "12.2(33)SRC5") flag = 1;
else if (version == "12.2(33)SRC6") flag = 1;
else if (version == "12.2(33)SRD") flag = 1;
else if (version == "12.2(33)SRD1") flag = 1;
else if (version == "12.2(33)SRD2") flag = 1;
else if (version == "12.2(33)SRD2a") flag = 1;
else if (version == "12.2(33)SRD3") flag = 1;
else if (version == "12.2(33)SRD4") flag = 1;
else if (version == "12.2(33)SRD4a") flag = 1;
else if (version == "12.2(33)SRD5") flag = 1;
else if (version == "12.2(33)SRD6") flag = 1;
else if (version == "12.2(33)SRD7") flag = 1;
else if (version == "12.2(33)SRD8") flag = 1;
else if (version == "12.2(33)SRE") flag = 1;
else if (version == "12.2(33)SRE0a") flag = 1;
else if (version == "12.2(33)SRE1") flag = 1;
else if (version == "12.2(33)SRE10") flag = 1;
else if (version == "12.2(33)SRE11") flag = 1;
else if (version == "12.2(33)SRE12") flag = 1;
else if (version == "12.2(33)SRE13") flag = 1;
else if (version == "12.2(33)SRE14") flag = 1;
else if (version == "12.2(33)SRE2") flag = 1;
else if (version == "12.2(33)SRE3") flag = 1;
else if (version == "12.2(33)SRE4") flag = 1;
else if (version == "12.2(33)SRE5") flag = 1;
else if (version == "12.2(33)SRE6") flag = 1;
else if (version == "12.2(33)SRE7") flag = 1;
else if (version == "12.2(33)SRE7a") flag = 1;
else if (version == "12.2(33)SRE8") flag = 1;
else if (version == "12.2(33)SRE9") flag = 1;
else if (version == "12.2(33)SRE9a") flag = 1;
else if (version == "12.2(33)XN") flag = 1;
else if (version == "12.2(33)XN1") flag = 1;
else if (version == "12.2(33)ZI") flag = 1;
else if (version == "12.2(33)ZZ") flag = 1;
else if (version == "12.2(34)SB1") flag = 1;
else if (version == "12.2(34)SB2") flag = 1;
else if (version == "12.2(34)SB3") flag = 1;
else if (version == "12.2(34)SB4") flag = 1;
else if (version == "12.2(34)SB4a") flag = 1;
else if (version == "12.2(34)SB4b") flag = 1;
else if (version == "12.2(34)SB4c") flag = 1;
else if (version == "12.2(34)SB4d") flag = 1;
else if (version == "15.0(2)ED") flag = 1;
else if (version == "15.0(2)ED1") flag = 1;
else if (version == "15.0(2)EH") flag = 1;
else if (version == "15.0(2)EJ") flag = 1;
else if (version == "15.0(2)EJ1") flag = 1;
else if (version == "15.0(2)EK") flag = 1;
else if (version == "15.0(2)EK1") flag = 1;
else if (version == "15.0(1)EX") flag = 1;
else if (version == "15.0(2)EX") flag = 1;
else if (version == "15.0(2)EX1") flag = 1;
else if (version == "15.0(2)EX3") flag = 1;
else if (version == "15.0(2)EX4") flag = 1;
else if (version == "15.0(2)EX5") flag = 1;
else if (version == "15.0(2a)EX5") flag = 1;
else if (version == "15.0(2)EY") flag = 1;
else if (version == "15.0(2)EY1") flag = 1;
else if (version == "15.0(2)EY2") flag = 1;
else if (version == "15.0(2)EY3") flag = 1;
else if (version == "15.0(2)EZ") flag = 1;
else if (version == "15.0(1)M") flag = 1;
else if (version == "15.0(1)M1") flag = 1;
else if (version == "15.0(1)M10") flag = 1;
else if (version == "15.0(1)M2") flag = 1;
else if (version == "15.0(1)M3") flag = 1;
else if (version == "15.0(1)M4") flag = 1;
else if (version == "15.0(1)M5") flag = 1;
else if (version == "15.0(1)M6") flag = 1;
else if (version == "15.0(1)M6a") flag = 1;
else if (version == "15.0(1)M7") flag = 1;
else if (version == "15.0(1)M8") flag = 1;
else if (version == "15.0(1)M9") flag = 1;
else if (version == "15.0(1)MR") flag = 1;
else if (version == "15.0(2)MR") flag = 1;
else if (version == "15.0(1)S") flag = 1;
else if (version == "15.0(1)S1") flag = 1;
else if (version == "15.0(1)S2") flag = 1;
else if (version == "15.0(1)S3a") flag = 1;
else if (version == "15.0(1)S4") flag = 1;
else if (version == "15.0(1)S4a") flag = 1;
else if (version == "15.0(1)S5") flag = 1;
else if (version == "15.0(1)S6") flag = 1;
else if (version == "15.0(1)SE") flag = 1;
else if (version == "15.0(1)SE1") flag = 1;
else if (version == "15.0(1)SE2") flag = 1;
else if (version == "15.0(1)SE3") flag = 1;
else if (version == "15.0(2)EX6") flag = 1;
else if (version == "15.0(2)EX7") flag = 1;
else if (version == "15.0(2)SE") flag = 1;
else if (version == "15.0(2)SE1") flag = 1;
else if (version == "15.0(2)SE2") flag = 1;
else if (version == "15.0(2)SE3") flag = 1;
else if (version == "15.0(2)SE4") flag = 1;
else if (version == "15.0(2)SE5") flag = 1;
else if (version == "15.0(2)SE6") flag = 1;
else if (version == "15.0(2)SE7") flag = 1;
else if (version == "15.0(2)SE9") flag = 1;
else if (version == "15.0(1)SY") flag = 1;
else if (version == "15.0(1)SY1") flag = 1;
else if (version == "15.0(1)SY10") flag = 1;
else if (version == "15.0(1)SY2") flag = 1;
else if (version == "15.0(1)SY3") flag = 1;
else if (version == "15.0(1)SY4") flag = 1;
else if (version == "15.0(1)SY5") flag = 1;
else if (version == "15.0(1)SY6") flag = 1;
else if (version == "15.0(1)SY7") flag = 1;
else if (version == "15.0(1)SY7a") flag = 1;
else if (version == "15.0(1)SY8") flag = 1;
else if (version == "15.0(1)SY9") flag = 1;
else if (version == "15.0(1)XA") flag = 1;
else if (version == "15.0(1)XA1") flag = 1;
else if (version == "15.0(1)XA2") flag = 1;
else if (version == "15.0(1)XA3") flag = 1;
else if (version == "15.0(1)XA4") flag = 1;
else if (version == "15.0(1)XA5") flag = 1;
else if (version == "15.1(1)MR5") flag = 1;
else if (version == "15.1(1)MR6") flag = 1;
else if (version == "15.1(1)SA") flag = 1;
else if (version == "15.1(1)SA1") flag = 1;
else if (version == "15.1(1)SA2") flag = 1;
else if (version == "15.1(1)XB1") flag = 1;
else if (version == "15.1(1)XB2") flag = 1;
else if (version == "15.1(1)XB3") flag = 1;
else if (version == "15.1(2)EY") flag = 1;
else if (version == "15.1(2)EY1") flag = 1;
else if (version == "15.1(2)EY1a") flag = 1;
else if (version == "15.1(2)EY2") flag = 1;
else if (version == "15.1(2)EY2a") flag = 1;
else if (version == "15.1(2)EY3") flag = 1;
else if (version == "15.1(2)EY4") flag = 1;
else if (version == "15.1(2)GC") flag = 1;
else if (version == "15.1(2)GC1") flag = 1;
else if (version == "15.1(2)GC2") flag = 1;
else if (version == "15.1(4)GC") flag = 1;
else if (version == "15.1(4)GC1") flag = 1;
else if (version == "15.1(4)GC2") flag = 1;
else if (version == "15.1(4)M") flag = 1;
else if (version == "15.1(4)M1") flag = 1;
else if (version == "15.1(4)M10") flag = 1;
else if (version == "15.1(4)M2") flag = 1;
else if (version == "15.1(4)M3") flag = 1;
else if (version == "15.1(4)M3a") flag = 1;
else if (version == "15.1(4)M4") flag = 1;
else if (version == "15.1(4)M5") flag = 1;
else if (version == "15.1(4)M6") flag = 1;
else if (version == "15.1(4)M7") flag = 1;
else if (version == "15.1(4)M8") flag = 1;
else if (version == "15.1(4)M9") flag = 1;
else if (version == "15.1(1)MR") flag = 1;
else if (version == "15.1(1)MR1") flag = 1;
else if (version == "15.1(1)MR2") flag = 1;
else if (version == "15.1(1)MR3") flag = 1;
else if (version == "15.1(1)MR4") flag = 1;
else if (version == "15.1(3)MR") flag = 1;
else if (version == "15.1(3)MRA") flag = 1;
else if (version == "15.1(3)MRA1") flag = 1;
else if (version == "15.1(3)MRA2") flag = 1;
else if (version == "15.1(1)S") flag = 1;
else if (version == "15.1(1)S1") flag = 1;
else if (version == "15.1(1)S2") flag = 1;
else if (version == "15.1(2)S") flag = 1;
else if (version == "15.1(2)S1") flag = 1;
else if (version == "15.1(2)S2") flag = 1;
else if (version == "15.1(3)S") flag = 1;
else if (version == "15.1(3)S0a") flag = 1;
else if (version == "15.1(3)S1") flag = 1;
else if (version == "15.1(3)S2") flag = 1;
else if (version == "15.1(3)S3") flag = 1;
else if (version == "15.1(3)S4") flag = 1;
else if (version == "15.1(3)S5") flag = 1;
else if (version == "15.1(3)S5a") flag = 1;
else if (version == "15.1(3)S6") flag = 1;
else if (version == "15.1(1)SG") flag = 1;
else if (version == "15.1(1)SG1") flag = 1;
else if (version == "15.1(1)SG2") flag = 1;
else if (version == "15.1(2)SG") flag = 1;
else if (version == "15.1(2)SG1") flag = 1;
else if (version == "15.1(2)SG2") flag = 1;
else if (version == "15.1(2)SG3") flag = 1;
else if (version == "15.1(2)SG4") flag = 1;
else if (version == "15.1(2)SG5") flag = 1;
else if (version == "15.1(2)SG6") flag = 1;
else if (version == "15.1(2)SG7") flag = 1;
else if (version == "15.1(2)SNG") flag = 1;
else if (version == "15.1(2)SNH") flag = 1;
else if (version == "15.1(2)SNH1") flag = 1;
else if (version == "15.1(2)SNI") flag = 1;
else if (version == "15.1(2)SNI1") flag = 1;
else if (version == "15.1(1)SY") flag = 1;
else if (version == "15.1(1)SY1") flag = 1;
else if (version == "15.1(1)SY2") flag = 1;
else if (version == "15.1(1)SY3") flag = 1;
else if (version == "15.1(1)SY4") flag = 1;
else if (version == "15.1(1)SY5") flag = 1;
else if (version == "15.1(1)SY6") flag = 1;
else if (version == "15.1(2)SY") flag = 1;
else if (version == "15.1(2)SY1") flag = 1;
else if (version == "15.1(2)SY2") flag = 1;
else if (version == "15.1(2)SY3") flag = 1;
else if (version == "15.1(2)SY4") flag = 1;
else if (version == "15.1(2)SY4a") flag = 1;
else if (version == "15.1(2)SY5") flag = 1;
else if (version == "15.1(2)SY6") flag = 1;
else if (version == "15.1(2)SY7") flag = 1;
else if (version == "15.1(1)T") flag = 1;
else if (version == "15.1(1)T1") flag = 1;
else if (version == "15.1(1)T2") flag = 1;
else if (version == "15.1(1)T3") flag = 1;
else if (version == "15.1(1)T4") flag = 1;
else if (version == "15.1(1)T5") flag = 1;
else if (version == "15.1(2)T") flag = 1;
else if (version == "15.1(2)T0a") flag = 1;
else if (version == "15.1(2)T1") flag = 1;
else if (version == "15.1(2)T2") flag = 1;
else if (version == "15.1(2)T2a") flag = 1;
else if (version == "15.1(2)T3") flag = 1;
else if (version == "15.1(2)T4") flag = 1;
else if (version == "15.1(2)T5") flag = 1;
else if (version == "15.1(3)S7") flag = 1;
else if (version == "15.1(3)SVG1c") flag = 1;
else if (version == "15.1(3)SVG2") flag = 1;
else if (version == "15.1(3)SVG2a") flag = 1;
else if (version == "15.1(3)SVG3") flag = 1;
else if (version == "15.1(3)SVG3a") flag = 1;
else if (version == "15.1(3)SVG3b") flag = 1;
else if (version == "15.1(3)SVG3c") flag = 1;
else if (version == "15.1(3)SVH") flag = 1;
else if (version == "15.1(3)SVH2") flag = 1;
else if (version == "15.1(3)SVH4") flag = 1;
else if (version == "15.1(3)SVI") flag = 1;
else if (version == "15.1(3)SVI1") flag = 1;
else if (version == "15.1(3)SVI1a") flag = 1;
else if (version == "15.1(3)SVI2") flag = 1;
else if (version == "15.1(3)T") flag = 1;
else if (version == "15.1(3)T1") flag = 1;
else if (version == "15.1(3)T2") flag = 1;
else if (version == "15.1(3)T3") flag = 1;
else if (version == "15.1(3)T4") flag = 1;
else if (version == "15.1(4)M0a") flag = 1;
else if (version == "15.1(4)M0b") flag = 1;
else if (version == "15.1(4)M11") flag = 1;
else if (version == "15.1(4)M12") flag = 1;
else if (version == "15.1(4)XB4") flag = 1;
else if (version == "15.1(4)XB5") flag = 1;
else if (version == "15.1(4)XB5a") flag = 1;
else if (version == "15.1(4)XB6") flag = 1;
else if (version == "15.1(4)XB7") flag = 1;
else if (version == "15.1(4)XB8") flag = 1;
else if (version == "15.1(4)XB8a") flag = 1;
else if (version == "15.1(1)XB") flag = 1;
else if (version == "15.2(1)E") flag = 1;
else if (version == "15.2(1)E1") flag = 1;
else if (version == "15.2(1)E2") flag = 1;
else if (version == "15.2(1)E3") flag = 1;
else if (version == "15.2(1)SC1a") flag = 1;
else if (version == "15.2(1)SC2") flag = 1;
else if (version == "15.2(1)SD1") flag = 1;
else if (version == "15.2(1)SD2") flag = 1;
else if (version == "15.2(1)SD3") flag = 1;
else if (version == "15.2(1)SD4") flag = 1;
else if (version == "15.2(1)SD6") flag = 1;
else if (version == "15.2(1)SD6a") flag = 1;
else if (version == "15.2(1)SD8") flag = 1;
else if (version == "15.2(2)E") flag = 1;
else if (version == "15.2(2)E1") flag = 1;
else if (version == "15.2(2)E2") flag = 1;
else if (version == "15.2(2)E4") flag = 1;
else if (version == "15.2(2a)E1") flag = 1;
else if (version == "15.2(2)S0d") flag = 1;
else if (version == "15.2(2)SC") flag = 1;
else if (version == "15.2(2)SNH") flag = 1;
else if (version == "15.2(3)E") flag = 1;
else if (version == "15.2(3)E1") flag = 1;
else if (version == "15.2(3)E2") flag = 1;
else if (version == "15.2(3)E3") flag = 1;
else if (version == "15.2(3)GCA") flag = 1;
else if (version == "15.2(3)GCA1") flag = 1;
else if (version == "15.2(3)XA") flag = 1;
else if (version == "15.2(3a)E") flag = 1;
else if (version == "15.2(3m)E2") flag = 1;
else if (version == "15.2(4)E") flag = 1;
else if (version == "15.2(4)E1") flag = 1;
else if (version == "15.2(4)M6b") flag = 1;
else if (version == "15.2(4)S0c") flag = 1;
else if (version == "15.2(4)S1c") flag = 1;
else if (version == "15.2(4)S8") flag = 1;
else if (version == "15.2(4)XB10") flag = 1;
else if (version == "15.2(4)XB11") flag = 1;
else if (version == "15.2(4m)E1") flag = 1;
else if (version == "15.2(2)EB") flag = 1;
else if (version == "15.2(2)EB1") flag = 1;
else if (version == "15.2(2)EB2") flag = 1;
else if (version == "15.2(2)EA1") flag = 1;
else if (version == "15.2(2)EA2") flag = 1;
else if (version == "15.2(2)EA3") flag = 1;
else if (version == "15.2(3)EA") flag = 1;
else if (version == "15.2(4)EA") flag = 1;
else if (version == "15.2(4)EA1") flag = 1;
else if (version == "15.2(4)EA3") flag = 1;
else if (version == "15.2(1)EY") flag = 1;
else if (version == "15.2(1)EY1") flag = 1;
else if (version == "15.2(1)EY2") flag = 1;
else if (version == "15.2(1)GC") flag = 1;
else if (version == "15.2(1)GC1") flag = 1;
else if (version == "15.2(1)GC2") flag = 1;
else if (version == "15.2(2)GC") flag = 1;
else if (version == "15.2(3)GC") flag = 1;
else if (version == "15.2(3)GC1") flag = 1;
else if (version == "15.2(4)GC") flag = 1;
else if (version == "15.2(4)GC1") flag = 1;
else if (version == "15.2(4)GC2") flag = 1;
else if (version == "15.2(4)GC3") flag = 1;
else if (version == "15.2(4)M") flag = 1;
else if (version == "15.2(4)M1") flag = 1;
else if (version == "15.2(4)M10") flag = 1;
else if (version == "15.2(4)M2") flag = 1;
else if (version == "15.2(4)M3") flag = 1;
else if (version == "15.2(4)M4") flag = 1;
else if (version == "15.2(4)M5") flag = 1;
else if (version == "15.2(4)M6") flag = 1;
else if (version == "15.2(4)M6a") flag = 1;
else if (version == "15.2(4)M7") flag = 1;
else if (version == "15.2(4)M8") flag = 1;
else if (version == "15.2(4)M9") flag = 1;
else if (version == "15.2(1)S") flag = 1;
else if (version == "15.2(1)S1") flag = 1;
else if (version == "15.2(1)S2") flag = 1;
else if (version == "15.2(2)S") flag = 1;
else if (version == "15.2(2)S0a") flag = 1;
else if (version == "15.2(2)S0c") flag = 1;
else if (version == "15.2(2)S1") flag = 1;
else if (version == "15.2(2)S2") flag = 1;
else if (version == "15.2(4)S") flag = 1;
else if (version == "15.2(4)S1") flag = 1;
else if (version == "15.2(4)S2") flag = 1;
else if (version == "15.2(4)S3") flag = 1;
else if (version == "15.2(4)S3a") flag = 1;
else if (version == "15.2(4)S4") flag = 1;
else if (version == "15.2(4)S4a") flag = 1;
else if (version == "15.2(4)S5") flag = 1;
else if (version == "15.2(4)S6") flag = 1;
else if (version == "15.2(4)S7") flag = 1;
else if (version == "15.2(2)SNG") flag = 1;
else if (version == "15.2(2)SNH1") flag = 1;
else if (version == "15.2(2)SNI") flag = 1;
else if (version == "15.2(1)SY") flag = 1;
else if (version == "15.2(1)SY0a") flag = 1;
else if (version == "15.2(1)SY1") flag = 1;
else if (version == "15.2(1)SY1a") flag = 1;
else if (version == "15.2(2)SY") flag = 1;
else if (version == "15.2(2)SY1") flag = 1;
else if (version == "15.2(1)T") flag = 1;
else if (version == "15.2(1)T1") flag = 1;
else if (version == "15.2(1)T2") flag = 1;
else if (version == "15.2(1)T3") flag = 1;
else if (version == "15.2(1)T3a") flag = 1;
else if (version == "15.2(1)T4") flag = 1;
else if (version == "15.2(2)T") flag = 1;
else if (version == "15.2(2)T1") flag = 1;
else if (version == "15.2(2)T2") flag = 1;
else if (version == "15.2(2)T3") flag = 1;
else if (version == "15.2(2)T4") flag = 1;
else if (version == "15.2(3)T") flag = 1;
else if (version == "15.2(3)T1") flag = 1;
else if (version == "15.2(3)T2") flag = 1;
else if (version == "15.2(3)T3") flag = 1;
else if (version == "15.2(3)T4") flag = 1;
else if (version == "15.3(3)M") flag = 1;
else if (version == "15.3(3)M1") flag = 1;
else if (version == "15.3(3)M2") flag = 1;
else if (version == "15.3(3)M3") flag = 1;
else if (version == "15.3(3)M4") flag = 1;
else if (version == "15.3(3)M5") flag = 1;
else if (version == "15.3(3)M6") flag = 1;
else if (version == "15.3(3)M7") flag = 1;
else if (version == "15.3(1)S") flag = 1;
else if (version == "15.3(1)S1") flag = 1;
else if (version == "15.3(1)S1e") flag = 1;
else if (version == "15.3(1)S2") flag = 1;
else if (version == "15.3(2)S") flag = 1;
else if (version == "15.3(2)S0a") flag = 1;
else if (version == "15.3(2)S1") flag = 1;
else if (version == "15.3(2)S2") flag = 1;
else if (version == "15.3(3)S") flag = 1;
else if (version == "15.3(3)S1") flag = 1;
else if (version == "15.3(3)S1a") flag = 1;
else if (version == "15.3(3)S2") flag = 1;
else if (version == "15.3(3)S3") flag = 1;
else if (version == "15.3(3)S4") flag = 1;
else if (version == "15.3(3)S5") flag = 1;
else if (version == "15.3(3)S6") flag = 1;
else if (version == "15.3(3)S7") flag = 1;
else if (version == "15.3(3)XB12") flag = 1;
else if (version == "15.3(1)SY") flag = 1;
else if (version == "15.3(1)T") flag = 1;
else if (version == "15.3(1)T1") flag = 1;
else if (version == "15.3(1)T2") flag = 1;
else if (version == "15.3(1)T3") flag = 1;
else if (version == "15.3(1)T4") flag = 1;
else if (version == "15.3(2)T") flag = 1;
else if (version == "15.3(2)T1") flag = 1;
else if (version == "15.3(2)T2") flag = 1;
else if (version == "15.3(2)T3") flag = 1;
else if (version == "15.3(2)T4") flag = 1;
else if (version == "15.4(1)CG") flag = 1;
else if (version == "15.4(1)CG1") flag = 1;
else if (version == "15.4(2)CG") flag = 1;
else if (version == "15.4(3)M") flag = 1;
else if (version == "15.4(3)M1") flag = 1;
else if (version == "15.4(3)M2") flag = 1;
else if (version == "15.4(3)M3") flag = 1;
else if (version == "15.4(3)M4") flag = 1;
else if (version == "15.4(3)M5") flag = 1;
else if (version == "15.4(1)S") flag = 1;
else if (version == "15.4(1)S1") flag = 1;
else if (version == "15.4(1)S2") flag = 1;
else if (version == "15.4(1)S3") flag = 1;
else if (version == "15.4(1)S4") flag = 1;
else if (version == "15.4(2)S") flag = 1;
else if (version == "15.4(2)S1") flag = 1;
else if (version == "15.4(2)S2") flag = 1;
else if (version == "15.4(2)S3") flag = 1;
else if (version == "15.4(2)S4") flag = 1;
else if (version == "15.4(3)S") flag = 1;
else if (version == "15.4(3)S1") flag = 1;
else if (version == "15.4(3)S2") flag = 1;
else if (version == "15.4(3)S3") flag = 1;
else if (version == "15.4(3)S4") flag = 1;
else if (version == "15.4(3)S5") flag = 1;
else if (version == "15.4(1)T") flag = 1;
else if (version == "15.4(1)T1") flag = 1;
else if (version == "15.4(1)T2") flag = 1;
else if (version == "15.4(1)T3") flag = 1;
else if (version == "15.4(1)T4") flag = 1;
else if (version == "15.4(2)T") flag = 1;
else if (version == "15.4(2)T1") flag = 1;
else if (version == "15.4(2)T2") flag = 1;
else if (version == "15.4(2)T3") flag = 1;
else if (version == "15.4(2)T4") flag = 1;
else if (version == "15.5(3)M") flag = 1;
else if (version == "15.5(3)M0a") flag = 1;
else if (version == "15.5(3)M1") flag = 1;
else if (version == "15.5(3)M2") flag = 1;
else if (version == "15.5(1)S") flag = 1;
else if (version == "15.5(1)S1") flag = 1;
else if (version == "15.5(1)S2") flag = 1;
else if (version == "15.5(1)S3") flag = 1;
else if (version == "15.5(2)S") flag = 1;
else if (version == "15.5(2)S1") flag = 1;
else if (version == "15.5(2)S2") flag = 1;
else if (version == "15.5(3)S") flag = 1;
else if (version == "15.5(3)S0a") flag = 1;
else if (version == "15.5(3)S1") flag = 1;
else if (version == "15.5(3)S1a") flag = 1;
else if (version == "15.5(3)S2") flag = 1;
else if (version == "15.5(3)SN") flag = 1;
else if (version == "15.5(1)T4") flag = 1;
else if (version == "15.5(1)T") flag = 1;
else if (version == "15.5(1)T1") flag = 1;
else if (version == "15.5(1)T2") flag = 1;
else if (version == "15.5(1)T3") flag = 1;
else if (version == "15.5(2)T") flag = 1;
else if (version == "15.5(2)T1") flag = 1;
else if (version == "15.5(2)T2") flag = 1;
else if (version == "15.5(2)T3") flag = 1;
else if (version == "15.6(1)S") flag = 1;
else if (version == "15.6(1)S1") flag = 1;
else if (version == "15.6(1)T") flag = 1;
else if (version == "15.6(1)T0a") flag = 1;
else if (version == "15.6(1)T1") flag = 1;
else if (version == "15.6(2)T") flag = 1;

cmds = make_list();
if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include ip msdp peer", "show running-config | include ip msdp peer");
    if (check_cisco_result(buf))
    {
      # Vulnerable if msdp enabled
      if (preg(pattern:"\s*ip\s*msdp\s*peer\s*[0-9]{1,3}(\.[0-9]{1,3}){3}", multiline:TRUE, string:buf))
      {
        flag = 1;
        cmds = make_list(cmds, "show running-config | include ip msdp peer");
      }
    }
    buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config | include include ipv6 multicast-routing", "show running-config | include ipv6 multicast-routing");
    if (check_cisco_result(buf2))
    {
      # Vulnerable if ipv6 multicast routing enabled
      if (preg(pattern:"\s*ipv6\s*multicast-routing", multiline:TRUE, string:buf2))
      {
        flag = 1;
        cmds = make_list(cmds, "show running-config | include ipv6 multicast-routing");
      }
    }
    else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : "CSCud36767, CSCuy16399",
    cmds     : cmds
  );
}
else audit(AUDIT_HOST_NOT, "affected");
