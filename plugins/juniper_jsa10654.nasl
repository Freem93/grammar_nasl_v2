#TRUSTED 4772ad45060a5f3576406934c33eacc2548ae55623adc07da8993b1cf5f356821ca0f5c6ffd792dc92271fdc5fa3ac669ac7bb6721c13e9b55af5415a3f7b0e15f092ac42e12dec65a81b4dd84042fac59dcd34e500125350984dc225ca30f0d074641d28564948510931428b35805cba95bc629555057fafa5123adcf88e107aa5d7a11d3267a7cc35a654cbc54250eb7829e9a1318beb176eb0913d1c491e962e430cc948ec3ccdfc52fe2efe6ca232adbccd9ec5ad93d847a73b72a7ebdffcdc85816b4dddfd0586b95ecbd116a804119e365890a0e233c0a07267dcafbfe63f2973a0a97a12108df72fe26c94e4dc2d7b10c21faa0102751991cab86c25c4235b96f1beff67edf165886470518a027db8c53134b6207bb93d9adae0bdf6c69d7615ef00cddee993d23cbb94e22a54fed88c6ca678fe7a09c29e0c6db3842a65c99db33ed02c34688ead9b9a996d441b85805b3367b1fbc3efe15b38f45ea507db7eeddb9fe5f8d446a1fb92a0ed2748339acf921cbe51335bad8924729603b03611fb2ad21f9db0124583fd0e108d1c0046643d8930997ebe8d0d595c68ca669ee328f509796b79b12446f76c7440e214fc3fcb73e02038d27cebd391acd1f27a2949c2991261c337c78a5369630ccaf0fff375964abe1914829db2f0a15011e8b7ef6ef488176ef4ca7a260de4be1543d52e3546dbe3097354e72712cd0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78425);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-6379");
  script_bugtraq_id(70365);
  script_osvdb_id(113080);
  script_xref(name:"JSA", value:"JSA10654");

  script_name(english:"Juniper Junos RADIUS Security Bypass (JSA10654)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a security bypass vulnerability. This
issue is caused by RADIUS accounting servers being used for
authentication requests. An authenticated attacker can exploit this to
bypass authentication.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10654");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10654.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D20';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.2X50'] = '12.2X50-D70';
fixes['12.3']    = '12.3R6';
fixes['13.1']    = '13.1R4-S3';
fixes['13.1X49'] = '13.1X49-D55';
fixes['13.1X50'] = '13.1X50-D30';
fixes['13.2']    = '13.2R4';
fixes['13.2X50'] = '13.2X50-D20';
fixes['13.2X51'] = '13.2X51-D26';
fixes['13.2X52'] = '13.2X52-D15';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == '13.2X51-D26')
  fix = '13.2X51-D26 or 13.2X51-D30';

# Check that a RADIUS server is configured
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system radius-server ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because RADIUS is not configured');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
