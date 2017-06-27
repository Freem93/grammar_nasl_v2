#TRUSTED 7037ba3c631a0c55ac95f9f2e9f1af9fdf86d16a2d89ba55dc35cef1c69d5d8062a5194a39522044be4c0a3f97770611ae25e9129a1a89efd5586d32d261fcd9e642f7f5ffc24c8ed56b1a2aa77b052322aae6aea8b9f1da71bc4c89d4bc9d4cb6908569ce9ebe7197f42184c7a0c861e47df92de0cdb717785a2a77fde483fd573ae773867e6b4e99fd1ea1987cbfd01ab9ae6f5ccc6a3e79f0457432c7dd312dd33a39a5107b95dbebd81368124ec38a6a8e452c65911995721074a3754925c9395a5c98a9815468bc8234f3df6e66ca012fa092de15b505cb62ad057cc0bedd3c6b013af1f25f21a12ae47dbfedd5d953e409559b47d6256eef91da8e74458957cadcceb58aa87b091e490f0dd7b560421d3491b34b686db8bffccfb9f0d1d5d484d35c3bba72dd81c7b55eba91150c9aeeea8a96be82a85d562c926a2715f7c308361c899987cea275be891706610a9ade12e5e2d5931c8755004d3ec0b0fcb72ba6220018045bc1a2e1dd9abbf21ca8ee9ad11584ca2916329fc9e227ee4b19918f44f3a17eb371a6a05258f42ec1ad97011e58d513c4702475578b020aca04f40ef27988d45cbb462b6c0cf2b4fd9107bc8496fabeabeb041b236a1b3b28a445b109b4f2c23177fc8b5f69a40ecc08f207b0d558b5c04fc156fc0da08e0ed789a346f80fce5f087703185ba4df8b772d956360303c764424563fd666b1
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(58569);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2014/07/03");

  script_cve_id("CVE-2012-0383");
  script_bugtraq_id(52758);
  script_osvdb_id(80701);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti35326");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerability (cisco-sa-20120328-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Network Address Translation (NAT) feature
contains a denial of service (DoS) vulnerability in the translation of
Session Initiation Protocol (SIP) packets. The vulnerability is caused
when packets in transit on the vulnerable device require translation
on the SIP payload. Cisco has released free software updates that
address this vulnerability. A workaround that mitigates the
vulnerability is available."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?61492259"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
if ( version == '12.4(24)MDA6' ) flag++;
if ( version == '12.4(24)MDA7' ) flag++;
if ( version == '12.4(24)MDA8' ) flag++;
if ( version == '12.4(24)MDA9' ) flag++;
if ( version == '12.4(24)MDB' ) flag++;
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB2' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\n\s*ip nat (inside|outside|enable)\n", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
