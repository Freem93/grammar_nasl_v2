#TRUSTED 1e4379f36471582c9dcbbc0822091ab352f51620090d0c4932f01c7f9c280a4235e2be8ee8be74b93a05633122799f8e532b97db461d58d7af87c5e1651bcfd04e45bc8d976070e2ce17d32b61fb31d0a69fd1f50b4c16c629d912535006f9e0771480a421588f199e54ef9c90617fb5691b39db72150d2b678553e008feee02372beadf23b6c7554984f86c677865cb0460167c8a40edebbe8888853bbef263099acf12b30b6c28add2a7fbdb223addee774051069931d5658c5bfd71b503e7849d165714abff7c31a3a56f574993bbc18650087f9d4147cb3bf3d916ddbd3880d3d0260199201d7573ac20f7bca4e05ee276b7a5e7c726dded7419b03221810198bccdd7d8591c82688d66679948a1003d10d2ceb1fed1454853771ab6681807cf81e4cc5009b9b277fbb60baef05497f0b633eba13bf2a22a31f8b7dc00886964f442ece7978335350afc1041475efab475932a4d41ca12f97acc4a1fe42441d583a8f6555146aa55b317c5c0c7ca00ade1744bc62bd0c9cea54a9acde15158cda28a9f5365578118f4d676e62229b8753a12e40df7a7824a08f089c01c42d04da5031524b09e92c9a7f806ee39a44a2f8773250fd2b057211c842c13c512205fceb94cab813e34ab645c4c09926a689912a8f2ad1bffa4676bdd4ab8c86cccef507a959fc115a842ad32964e489f473fbcf65a6aab2f99490a542e48a317
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72000);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2014-0618");
  script_bugtraq_id(64769);
  script_osvdb_id(101864);
  script_xref(name:"JSA", value:"JSA10611");

  script_name(english:"Juniper Junos SRX Series flowd Remote DoS (JSA10611)");
  script_summary(english:"Checks the Junos version, model, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos SRX series device is affected by a denial of service
vulnerability in the flow daemon (flowd) when handling certain valid
HTTP protocol messages. A remote attacker can exploit this to crash
the device.

Note that this issue only affects devices configured as a Unified
Access Control (UAC) enforcer in a UAC network with Captive Portal
authentication enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10611");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10611.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/16");

  script_set_attribute(attribute:"potential_vulnerability", value:"true"); 
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

check_model(model:model, flags:SRX_SERIES, exit_on_fail:TRUE);

if (compare_build_dates(build_date, '2013-12-12') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['10.4'] = '10.4R16';
fixes['11.4'] = '11.4R8';
fixes['12.1'] = '12.1R7';
fixes['12.1X44'] = '12.1X44-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check that UAC enforcer and captive portal are enabled
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  patterns = make_list(
    "^set services unified-access-control infranet-controller",
    "^set services captive-portal"
  );

  foreach pattern (patterns)
  {
    if (!junos_check_config(buf:buf, pattern:pattern))
      audit(AUDIT_HOST_NOT,
      'affected because it is not configured as a UAC enforcer with captive portal enabled');
  }

  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
