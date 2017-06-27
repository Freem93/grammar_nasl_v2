#TRUSTED 350bdcd6d565b0a80fc88eed4dacca8ae1b31bea460ef37c45390af65ac71ddb1e745b2f0db3f21d7bb6c997b593b9e86235f282ef9d68fb2fc931d7b5c65a64d66b2571c14138f37797d3f6bd918fc48a4507def2a59789db6ae2e847896d4a7580340aebfe39b2ceba66cb1f75b67712cba089954ef03c5e9fc54a2e3bd55ac1c1705b5bcf8a9928d2e941a6c25ed5799497ca8847524d3eebd65170a52b014bf0a839be80803be42a07ecd712e6115a5b9ea45ebc0c5778740934e81c7e4f006e1c2a05f3e44f10cfe948df8bc24b4cc7cc7e003c3922a63f965d84b7bd994d4d15d50c079b790b0aca95541d750c7abfcd1ef425f7be70c3a7c97bac0c25a95a863d4b383ef01784321d346c60b07af0c7a4edc9d3514b8c56f93cae4683ef17fe1f7048ff479198b06451fc5850c04e6bdbe4b50093d0956b146c193307799bc6278de445243d4415df498c8fc054bc62781490675b41b42c953232f52ecb78fca1fb72f29e2203c33c6689f33555900f84f8222f4ca09aa786ec3f22a6d8efb77040c4a98f84343618fa46df8801bf9579868aaba046e3128a1e921b3f6a103ca9b556f2eb1363c04fcc77f682b9c86510c2c88d214e2f02ff9f8fd054cf9f95b69a588c877fd90e4b2abe02c054b350466877b2f39901b9c53e2c4de113ed1a49a3bab1811ef0c43ce6f4427d0ee705557b40d6e435f40463cc218491
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82797);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2015-3005");
  script_bugtraq_id(74016);
  script_osvdb_id(120482);
  script_xref(name:"JSA", value:"JSA10677");

  script_name(english:"Juniper Junos SRX Series Dynamic VPN XSS (JSA10677)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a cross-site scripting
vulnerability due to a flaw in Dynamic VPN. A remote attacker can
exploit this to view sensitive information or session credentials.

Note that this issue only affects Junos devices with Dynamic VPN
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10677");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10677.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ('SRX' >!< model) audit(AUDIT_DEVICE_NOT_VULN, model);

fixes = make_array();
fixes['12.1X44'] = '12.1X44-D45';
fixes['12.1X46'] = '12.1X46-D30';
fixes['12.1X47'] = '12.1X47-D20';
fixes['12.3X48'] = '12.3X48-D10';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Dynamic VPN must be enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set security ike gateway (\S+) dynamic "; # Check for dynamic attribute
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because Dynamic VPN is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xss:TRUE);
