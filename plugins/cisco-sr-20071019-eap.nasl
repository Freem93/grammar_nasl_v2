#TRUSTED a24a0afa5180ae245c2eb62a42dc8f9a218167a34e4f64538ad5b348f7b40fbeb37dce5bafafabb274a12058a67b986acae3c8a252b8f3758f8b8277c9d6d53680a19e376128b51dd429022b3c4720567a9e84a98ba3a6be0bbdb6950d110744c82cbe38cc7773e6527f9d3454f75c532855b8c73f1e045ac79721bc1630722ea10e34c49a0e7ceb5269dcbb996d9c9d441136092b7c3c9d87d8efe97ba66f90ae3ab7764a56d178b3852240f179ea85f0cf03e48606834d463b8beae1c4b7165cde8942cb0d5a6bbbbc40dc2d49996491e213b9c7682c8915d6d3811eb11f688202ec64306dbe3299349cf7f93d3fcbcf9a3202d1f52611f3beec62d5393c399f6c9668e4f998c0720431c4db81b49948ddadf0481a01a32c08b9bc71cd683a3519be665e6c695491de7767264a72f8ed9b5769bf7b86a8da9c391c07749afb842d067649004108d69b8795e8790e82bd4e9bb4f780e8d07318cd16fda7fd7f094ecc3d7fd24d2ac41d978d368cf2fc061662190c19a119bc5dbac44ed14761ebea212967a4c39e98b6cb735c193199ca72dd158eba81af401901a42310357134c74c9eff4486e96ca59db0120d87dc555d44ec1971a315157063b1e67cb1f2bfdd8ed122ba5702f516885e201dcd65a8bc91cc35ef13dda2c2d7f2766521e0bafbefe74496188362f274b469a18e4a298a8f2bc3acbfeaa07b071f8416ee27
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(68991);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2015/01/15");

  script_cve_id("CVE-2007-5651");
  script_bugtraq_id(26139);
  script_osvdb_id(40873);
  script_xref(name:"CISCO-BUG-ID", value:"CSCsb45696");
  script_xref(name:"CISCO-BUG-ID", value:"CSCsj56438");
  script_xref(name:"CISCO-SR", value:"cisco-sr-20071019-eap");

  script_name(english:"Cisco IOS Extensible Authentication Protocol Vulnerability (cisco-sr-20071019-eap)");
  script_summary(english:"Checks IOS version and running config");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Cisco IOS running on the remote host has a denial of
service vulnerability.  The Extensible Authentication Protocol (EAP)
implementation does not properly process EAP packets, which could cause
the device to crash.  A remote, unauthenticated attacker could exploit
this to execute arbitrary code."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.cr0.org/paper/hacklu2007-final.pdf");
  # http://tools.cisco.com/security/center/content/CiscoSecurityResponse/cisco-sr-20071019-eap
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e2a777c");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in the Cisco Security Response
cisco-sr-20071019-eap."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
vuln = 0;

if (deprecated_version(version, "12.3JA")) vuln++;
if (check_release(version:version, patched:make_list("12.4(10b)JA"))) vuln++;
if (deprecated_version(version, "12.3JEA")) vuln++;
if (deprecated_version(version, "12.3JEB")) vuln++;
if (check_release(version:version, patched:make_list("12.3(8)JEC"))) vuln++;
if (deprecated_version(version, "12.4JX")) vuln++;
if (check_release(version:version, patched:make_list("12.4(5)XW"))) vuln++;  # the advisory says 12.4.XW5, i assume that is 12.4(5)XW
if (check_release(version:version, patched:make_list("12.1(27b)E2"))) vuln++;
if (check_release(version:version, patched:make_list("12.1(22)EA6"))) vuln++;
if (check_release(version:version, patched:make_list("12.1(26)EB2"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)EW6"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)S13"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)SXF9"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(18)ZY1"))) vuln++; # the advisory says 12.2.18-ZY1
if (check_release(version:version, patched:make_list("12.2(20)S13"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)EWA4"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)EX"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)FX"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)SED"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(25)SG"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(31)SB6"))) vuln++;
if (check_release(version:version, patched:make_list("12.2(33)SRA4"))) vuln++;

if (!vuln)
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS', version);

override = 0;

if (
  get_kb_item("Host/local_checks_enabled") &&
  running_config = get_kb_item("Secret/Host/Cisco/show_running")
)
{
  config_vuln = 0;

  # two requirements for CSCsj56438 to be present on APS and 1310 Wireless Bridges:
  #
  # 1) The device must be running IOS in autonomous mode:
  #    "Access Points and 1310 Wireless Bridges running in LWAPP mode are not affected.
  #     Access Points in autonomous mode will have -K9W7- in the image names,
  #     while Access Points in LWAPP mode will have -K9W8- in their name."
  #
  # 2) "To determine if EAP is enabled on the Access Point, log into the device and issue the show running-config CLI
  #     command. If the output contains the
  #
  #      authentication open eap 'method_name'
  #    or
  #      authentication network-eap 'method_name'
  #
  #    then the device is vulnerable."
  feature_set = get_kb_item("Host/Cisco/IOS/FeatureSet");

  if (
    feature_set == 'K9W7' &&
    ('authentication open eap' >< running_config || 'authentication network-eap' >< running_config)
  )
  {
    config_vuln++;
  }

  # Two possible vulnerable configurations for CSCsj56438 on Catalyst 6500 Series and 7600 Series Wireless LAN
  # Services Module.  The device is vulnerable if the output of "show running-config" contains either of the following:
  #
  # 1) wlccp authentication-server client <any | eap | leap> <list_name>
  #
  # 2) wlccp authentication-server infrastructure <list>
  if (
    running_config =~ 'wlccp authentication-server client (any|eap|leap)' ||
    'wlccp authentication-server infrastructure' >< running_config
  )
  {
    config_vuln++;
  }

  # IOS switches are vulnerable to CSCsb45696 if the output of "show running-config" contains either of the following:
  #
  # dot1x pae authenticator
  # dot1x pae both
  if ('dot1x pae authenticator' >< running_config || 'dot1x pae both' >< running_config )
  {
    config_vuln++;
  }

  # There are configuration checks for CSCsc55249 (CatOS) but this plugin currently doesn't support authenticated
  # scans of CatOS devices

  if (!config_vuln)
    exit(0, 'The remote host is not affected.  The IOS version is unpatched, but the device is not using a vulnerable configuration.');
}

security_hole(port:0, extra:cisco_caveat(override));

