#TRUSTED 8d8630e6db31fcd9d7505b817c8f5d481fc7c5d55f1f4629a1f80297d74910fb4c0f9c913d3c7037a41b0e81a88bc1b6b95bbc9fa9e01718d19b8f6af0fabcecb888134dee8502cb874db919bcd5f2a447c1a594c085ed293c3bdec3348d87a879afcc2fa610a7a85f894e820b01c57bd306bdf4c9e96bc6e2dc340b99d93c079f043bf45fe78e94cf2fb1c70cd809e6e7e0c5f1a7a9d8a7d6982eb2a114cbcac4c59c493169bbc81499e45bd85dab7ab3159e58f9efb9f29cfa30836de82b93ae8a138bd78abcf8e3a097847c1a47fe741deb4fac477634d851805e8f74d5edf5fb2951d2215128b6abb969f4ccec12825b0116cee9e462316f9bbb8e8051cb3d79120791f985feb77c66db8ad2b3b2379b0861e8865245d4064e4ca5ef21cb11a6401f4f921d76789359ea80638b015b8ab88dde2c29723fa8f2c53e9928929dbeee6a70b27a87daa8cea3b4f94186c7ea0ac36715cc7ea9eeaa81dc5973262419435a51b4c32bfd206dbd6efcec09c421538ef4add524924f3d608e7185fdbfa5972d45348708bd498598615295c29b0aa07b82eb94cb20243474001430363565077fe3446d9049b04199e0134b2a221e44b80be8b9e3cd65150cc9b1fc028e1d511b77b2362b99c700bc7d6af19fdfe301515523c5d2e30a69e3cb13d910f6654e7ca5bfb2f092e174e7e6b50ca22a59f68fdc8c1f8f5acc20b90c2df979
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99524);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/04/20");

  script_cve_id("CVE-2017-2312");
  script_bugtraq_id(97611);
  script_osvdb_id(155439);
  script_xref(name:"JSA", value:"JSA10777");
  script_xref(name:"IAVA", value:"2017-A-0121");

  script_name(english:"Juniper Junos Routing Protocol Daemon LDP Packet DoS (JSA10777)");
  script_summary(english:"Checks the Junos version and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the remote
Juniper Junos device is affected by a memory leak issue in the routing
protocol daemon (rpd) when handling a specific LDP packet, which over
time will consume memory that cannot be freed without restarting the
rpd process. An authenticated, adjacent attacker can exploit this, by
repeatedly using this kind of packet, to cause the rpd process to
crash and reload, resulting in a denial of service condition. Note
that this issue affects devices with either IPv4 or IPv6 LDP enabled
via the '[protocols ldp]' configuration. Furthermore, the interface on
which the packet arrives needs to have LDP enabled.

Nessus has not tested for this issue but has instead relied only on
the device's self-reported version and current configuration.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10777&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1fa1895d");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10777.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
# Workaround is available
if (report_paranoia < 2) audit(AUDIT_PARANOID);

fixes = make_array();

fixes['13.3'] = '13.3R10';
fixes['14.1'] = '14.1R8';
fixes['14.2R7'] = '14.2R7-S6';
fixes['14.2'] = '14.2R8';
fixes['15.1F2'] = '15.1F2-S14';
fixes['15.1F6'] = '15.1F6-S4';
fixes['15.1F'] = '15.1F7';
fixes['15.1R4'] = '15.1R4-S7';
fixes['15.1R'] = '15.1R5';
fixes['15.1X49'] = '15.1X49-D70';
fixes['15.1X53'] = '15.1X53-D63'; # or 15.1X53-D70 or 15.1X53-D230
fixes['16.1'] = '16.1R2';
fixes['16.2'] = '16.2R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show ldp statistics");
if (buf)
{
  if (preg(string:buf, pattern:"LDP.* instance is not running", icase:TRUE, multiline:TRUE))
    audit(AUDIT_HOST_NOT, "affected because LDP is not enabled"); 
  else
    override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
