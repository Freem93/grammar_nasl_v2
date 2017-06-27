#TRUSTED 847531fe33c664c99ae484558bc309ccf9eb42551b768807f2494f3015f9bcb57586dcc3d91d0e3d73cb68834c2b4909f6f3264fcbf78c9a43981ce48ad98790a224fdee1bd26cf3a13ab9bece466c6b4014436d13e3904ade65d1b7ff080b0785b1da6d3f44ab6ecc0e2581d3fb778bec1a29603ff29054d82f4b3852109edef45a2c97c96fbf39005735421a6d6863be2d55721a67bd1d727562a157d12eb7affd04d82f5341637b3bb2b848070db8cb41d3f839cdc16a8587951819856682bc3823964857d799f0f085310427f0973c0ee3f5b95edfad86d8666acd002df9d67a80fe68b913d24d26e69a77f0afb60c62e0f488f6b8640c4f1aeafc87ae17519ee543760beca16d6b0c55a6dc82a75517a47ab7e8baf2177be4011c6bbe82b9c2831e0b0d367486d2bac320292ad40cc75341ab67e40ca93d647d32f982f88064182b42fc1e11bc3f41cedd047ed2c03c5a1a5982a10408b20fb1c2984d349a61ef04a7380f78baf05eaee769a1c90268ad99d35284aad1538e55472f4f613e3ec7950427908f6caaf14a6dc58e65b337a01e11f2dd27b5727d6b0fbac6281d3a4529bf1ade9f9250eb59e4994805df6fe26dc918d1df56e3ad3bb07c3e4d45ae87ecf0ff2a5620e78708811cda01b8b52ca4aed33d5e09725358cd03a0325dfd621c39b3104935439690a8928b8809309ed3cf6618795d903aa2d6b05894
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17782);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/08/11");

  script_cve_id("CVE-2006-4950");
  script_bugtraq_id(20125);
  script_osvdb_id(29034);
  script_xref(name:"CERT", value:"123140");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb04965");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb06658");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20060920-docsis");

  script_name(english:"DOCSIS Read-Write Community String Enabled in Non-DOCSIS Platforms");
  script_summary(english:"Checks IOS version");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"Vulnerable versions of Cisco IOS contain a default hard-coded
community string when SNMP is enabled on the device.  An additional
read-write community string may be enabled if the device is configured
for SNMP management, which would allow privilege access to the
device."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20060920-docsis
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc14beaf");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20060920-docsis."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencie("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
override = 0;

if (version == '12.4(2)T4') flag++;
else if (version == '12.4(2)T3') flag++;
else if (version == '12.4(2)T2') flag++;
else if (version == '12.4(2)T1') flag++;
else if (version == '12.4(2)T') flag++;
else if (version == '12.4(2)MR1') flag++;
else if (version == '12.4(2)MR') flag++;
else if (version == '12.4(1a)') flag++;
else if (version == '12.4(1)') flag++;
else if (version == '12.3(14)YX1') flag++;
else if (version == '12.3(14)YU1') flag++;
else if (version == '12.3(14)YU') flag++;
else if (version == '12.3(14)YT1') flag++;
else if (version == '12.3(14)YT') flag++;
else if (version == '12.3(11)YS1') flag++;
else if (version == '12.3(11)YS') flag++;
else if (version == '12.3(14)YQ7') flag++;
else if (version == '12.3(14)YQ6') flag++;
else if (version == '12.3(14)YQ5') flag++;
else if (version == '12.3(14)YQ4') flag++;
else if (version == '12.3(14)YQ3') flag++;
else if (version == '12.3(14)YQ2') flag++;
else if (version == '12.3(14)YQ1') flag++;
else if (version == '12.3(14)YQ') flag++;
else if (version == '12.3(14)YM7') flag++;
else if (version == '12.3(14)YM6') flag++;
else if (version == '12.3(14)YM5') flag++;
else if (version == '12.3(14)YM4') flag++;
else if (version == '12.3(14)YM3') flag++;
else if (version == '12.3(14)YM2') flag++;
else if (version == '12.3(11)YK2') flag++;
else if (version == '12.3(11)YK1') flag++;
else if (version == '12.3(11)YK') flag++;
else if (version == '12.3(11)YJ') flag++;
else if (version == '12.3(8)YI3') flag++;
else if (version == '12.3(8)YI2') flag++;
else if (version == '12.3(8)YI1') flag++;
else if (version == '12.3(8)YH') flag++;
else if (version == '12.3(8)YG4') flag++;
else if (version == '12.3(8)YG3') flag++;
else if (version == '12.3(8)YG2') flag++;
else if (version == '12.3(8)YG1') flag++;
else if (version == '12.3(8)YG') flag++;
else if (version == '12.3(11)YF4') flag++;
else if (version == '12.3(11)YF3') flag++;
else if (version == '12.3(11)YF2') flag++;
else if (version == '12.3(11)YF1') flag++;
else if (version == '12.3(11)YF') flag++;
else if (version == '12.3(8)YD1') flag++;
else if (version == '12.3(8)YD') flag++;
else if (version == '12.3(8)YA1') flag++;
else if (version == '12.3(8)YA') flag++;
else if (version == '12.3(8)XY7') flag++;
else if (version == '12.3(8)XY6') flag++;
else if (version == '12.3(8)XY5') flag++;
else if (version == '12.3(8)XY4') flag++;
else if (version == '12.3(8)XY3') flag++;
else if (version == '12.3(8)XY2') flag++;
else if (version == '12.3(8)XY1') flag++;
else if (version == '12.3(8)XY') flag++;
else if (version == '12.3(11)XL1') flag++;
else if (version == '12.3(11)XL') flag++;
else if (version == '12.3(4)XD3') flag++;
else if (version == '12.3(4)XD2') flag++;
else if (version == '12.3(4)XD1') flag++;
else if (version == '12.3(4)XD') flag++;
else if (version == '12.3(14)T7') flag++;
else if (version == '12.3(14)T6') flag++;
else if (version == '12.3(14)T5') flag++;
else if (version == '12.3(14)T3') flag++;
else if (version == '12.3(14)T2') flag++;
else if (version == '12.3(14)T1') flag++;
else if (version == '12.3(14)T') flag++;
else if (version == '12.3(11)T6') flag++;
else if (version == '12.3(11)T5') flag++;
else if (version == '12.3(11)T4') flag++;
else if (version == '12.3(11)T3') flag++;
else if (version == '12.3(11)T2') flag++;
else if (version == '12.3(11)T') flag++;
else if (version == '12.3(8)T9') flag++;
else if (version == '12.3(8)T8') flag++;
else if (version == '12.3(8)T7') flag++;
else if (version == '12.3(8)T6') flag++;
else if (version == '12.3(8)T5') flag++;
else if (version == '12.3(8)T4') flag++;
else if (version == '12.3(8)T3') flag++;
else if (version == '12.3(8)T1') flag++;
else if (version == '12.3(8)T') flag++;
else if (version == '12.3(7)T9') flag++;
else if (version == '12.3(7)T8') flag++;
else if (version == '12.3(7)T7') flag++;
else if (version == '12.3(7)T6') flag++;
else if (version == '12.3(7)T4') flag++;
else if (version == '12.3(7)T3') flag++;
else if (version == '12.3(7)T2') flag++;
else if (version == '12.3(7)T10') flag++;
else if (version == '12.3(7)T1') flag++;
else if (version == '12.3(7)T') flag++;
else if (version == '12.3(4)T9') flag++;
else if (version == '12.3(4)T8') flag++;
else if (version == '12.3(4)T7') flag++;
else if (version == '12.3(4)T6') flag++;
else if (version == '12.3(4)T4') flag++;
else if (version == '12.3(4)T3') flag++;
else if (version == '12.3(4)T2') flag++;
else if (version == '12.3(4)T11') flag++;
else if (version == '12.3(4)T10') flag++;
else if (version == '12.3(4)T1') flag++;
else if (version == '12.3(4)T') flag++;
else if (version == '12.2(15)ZJ3') flag++;
else if (version == '12.2(15)ZJ2') flag++;
else if (version == '12.2(15)ZJ1') flag++;
else if (version == '12.2(15)ZJ') flag++;
else if (version == '12.2(15)MC2b') flag++;
else if (version == '12.2(15)MC2a') flag++;
else if (version == '12.2(15)MC2') flag++;
else if (version == '12.2(15)MC1c') flag++;
else if (version == '12.2(15)MC1b') flag++;
else if (version == '12.2(15)MC1a') flag++;
else if (version == '12.2(15)MC1') flag++;
else if (version == '12.2(8)MC2d') flag++;
else if (version == '12.2(8)MC2c') flag++;
else if (version == '12.2(8)MC2b') flag++;
else if (version == '12.2(8)MC2a') flag++;
else if (version == '12.2(8)MC2') flag++;
else if (version == '12.2(8)MC1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_community", "show snmp community");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Community name:", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
