#TRUSTED 368ca16ae1a38c2a0bd20e06fb9aa43fe2b2f7aa7b0ceb8fe68feaf5c47f241ea369d398e6919f432612bb9655d6bba044bdd57783a3f22b1538b83e4e45f5f02a78482cd32fd410bef1c74481804804f7155d40799773c4917351d088d58db4766213b3dfd5a62539d451d601877c7cf16d04966eb3316dc62951048793306d0ea5295beebc1b532a3e70420a93d77000b4366ea8d577144812d4904c8a9ff8affa55749f2b57b272eeb46eb71e4c648f99222dc49740b4664698c9004e060abf9b79f0c0fda3a8b8a033a4c6174913bb4678e7307c4e04ed2fb3e9336ccd0f6f9e937eb9cff90aae88745ad46f59dbc474df2e70dc97618acee218b1c736a93b4eb8a52fba4a147e9c8b4625fd25f48391e173756f6d5f038c56c84af15b4c444338e6a7c2202c313f1eb391ed300854b37708a8da79b85ed0d098eb1557fa722be01b0c8d5e8392fca4a2fd1778ca1a790a25daf6bd64933a98fbeb2d78b7bd9c7ec399efff74069a9256e435f5c6bc234dba1fa97c1d518db5a26eb026ed1e4f5308158f3d4a57536a481a6ae488a234033f63c89aa36411c00af18a3009406ee079f2fa75062d5c9efb928b913e75653ecbef297732cbd2089f9e4ce5bbed5763b653e236e7db972f52316b1dc9785cc800f386140150a38d9f1d56c5e64b79fb9d40eb078f77f43b511cfe9d9150a4599ac006162f58aad5704826a285
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73344);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-2113");
  script_bugtraq_id(66467);
  script_osvdb_id(104968);
  script_xref(name:"CISCO-BUG-ID", value:"CSCui59540");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140326-ipv6");

  script_name(english:"Cisco IOS Software IPv6 Denial of Service (cisco-sa-20140326-ipv6");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS
running on the remote host is affected by a denial of service
vulnerability in the IPv6 protocol stack. This issue exists due to
improper handling of certain, unspecified types of IPv6 packets. An
unauthenticated, remote attacker could potentially exploit this issue
by sending a specially crafted IPv6 packet resulting in a denial of
service.

Note that this only affects hosts with IPv6 enabled.");
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
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/04");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
fixed_ver = "";
cbi = "CSCui59540";

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

#15.2E
if (ver == "15.2(1)E" || ver == "15.2(1)E1")
  fixed_ver = "15.2(1)E2";
#15.2EY
else if (ver == "15.2(1)EY")
  fixed_ver = "15.2(1)E2";
#15.2GC
else if (ver == "15.2(4)GC")
  fixed_ver = "15.2(4)GC1";
#15.2JA
else if (ver == "15.2(4)JA" || ver == "15.2(4)JA1")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JAY
else if (ver == "15.2(4)JAY")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JB
else if (ver == "15.2(4)JB" || ver == "15.2(4)JB1" || ver == "15.2(4)JB2" || ver == "15.2(4)JB3" || ver == "15.2(4)JB3a")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2JN
else if (ver == "15.2(4)JN")
  fixed_ver = "Refer to the vendor for a fix.";
#15.2M
else if (ver == "15.2(4)M" || ver == "15.2(4)M1" || ver == "15.2(4)M2" || ver == "15.2(4)M3" || ver == "15.2(4)M4" || ver == "15.2(4)M5")
  fixed_ver = "15.2(4)M6";
#15.2S
else if (ver == "15.2(4)S" || ver == "15.2(4)S0c" || ver == "15.2(4)S1" || ver == "15.2(4)S2" || ver == "15.2(4)S3" || ver == "15.2(4)S3a" || ver == "15.2(4)S4" || ver == "15.2(4)S4a")
  fixed_ver = "15.2(4)S5";
#15.2XB
else if (ver == "15.2(4)XB10")
  fixed_ver = "Refer to the vendor for a fix.";
#15.3M
else if (ver == "15.3(3)M" || ver == "15.3(3)M1")
  fixed_ver = "15.3(3)M2";
#15.3S
else if (ver == "15.3(1)S" || ver == "15.3(1)S1" || ver == "15.3(1)S1e" || ver == "15.3(1)S2" || ver == "15.3(2)S" || ver == "15.3(2)S0a" || ver == "15.3(2)S0xa" || ver == "15.3(2)S1" || ver == "15.3(2)S1b" || ver == "15.3(2)S1c" || ver == "15.3(2)S2" || ver == "15.3(3)S" || ver == "15.3(3)S0b" || ver == "15.3(3)S1" || ver == "15.3(3)S1a")
  fixed_ver = "15.3(3)S2";
#15.3T
else if (ver == "15.3(1)T" || ver == "15.3(1)T1" || ver == "15.3(1)T2" || ver == "15.3(1)T3" || ver == "15.3(2)T" || ver == "15.3(2)T1" || ver == "15.3(2)T2")
  fixed_ver = "15.3(2)T3 / 15.3(1)T4";



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
