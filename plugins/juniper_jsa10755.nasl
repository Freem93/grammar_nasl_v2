#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92513);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/10/27 19:44:38 $");

  script_cve_id("CVE-2016-1280");
  script_bugtraq_id(91761);
  script_osvdb_id(141472);
  script_xref(name:"JSA", value:"JSA10755");

  script_name(english:"Juniper Junos Certificate Validation Bypass (JSA10755)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a security bypass vulnerability due to
improper validation of self-signed certificates used for IKE and
IPsec. An unauthenticated, remote attacker can exploit this, via a
specially crafted self-signed certificate, to bypass certificate
validation and intercept network traffic.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10755");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
advisory JSA10755. Alternatively, configure all PKI-VPN tunnels to
accept only Distinguished Name (DN) as the remote peer's IKE ID.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D52'; # or 12.1X44-D55
fixes['12.1X46'] = '12.1X46-D37'; # or 12.1X46-D40
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'   ] = '12.3R12';
fixes['12.3X48'] = '12.3X48-D20';
fixes['12.3'   ] = '13.3R10';
fixes['14.1'   ] = '14.1R8';
fixes['14.1X53'] = '14.1X53-D40';
fixes['14.2'   ] = '14.2R7';
fixes['15.1R'  ] = '15.1R4';
fixes['15.1X49'] = '15.1X49-D20';
fixes['15.1X53'] = '15.1X53-D60';
fixes['16.1R'  ] = '16.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix ==  "12.1X44-D52")
  fix += " or 12.1X44-D55";
if (fix == "12.1X46-D37")
  fix += " or 12.1X46-D40";

junos_report(ver:ver, fix:fix, model:model, severity:SECURITY_WARNING);
