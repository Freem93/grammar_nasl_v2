#TRUSTED 1009cebbcb1eb39fa205325efbb4b23f9a0f4d0903518a30837ce48a673554d784bbf210f3a6f30477ab1651d9b4bdf0b313ac2911da0df1256c8923e63d9f388b117339074dce4c438c0ffeadc10a20eb22c8f0d51f5b6554895496630989ed76bb7293706a7833fd3243ad540642e3a280f8177334fbc2300e69a3485dd462300c8f8ce3c2d3a25d5b0aedc819ddb34a49e1d8916d5cf8492c021286e6a85302f4a57a7b853bb94c60c9376829864d1b9882e9d53b9cf958d48391489a902204f388f0ac8908ee221a3740eea91d1e1406a6a41c991d77032a330e106312cb20e92a80a3b599c84cf61bde1ce790f5f9e67f1b8837cd98fc0c712d6bb8bcf9def3512044d7d3477f0bbaee049634a5fe0fb7fbab04b84ae224e4ddc97449e42c82b00747bfd450c3079a4178d52cb1ff1357a53faedcb60963c21f3fbef357d98d3d8e20809cfaa99b35416b837b02e2c1b0288cc12b0c5a0da51dff0ddee720e1509448fd3b030ed2380c8e8364ac988a9873f38bf14722742c31db437829a25606b09b4c46340183d1dad330dc83e00072d5016ac786c7265110a9685dcb3859d8b45f16b319d57040cd87073a657fd434f9bcb383b1bcd5f2fde5fdb5b038cdedfe60c5b21a989c9f1aa9fe888c9bc2e21cfd8e1f146c331cea5e3aa1764e2bab239edec38bf512a8c3814dc182bce37718c746fd2ce44d0b19906f4bb4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97211);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/06");

  script_cve_id("CVE-2017-3807");
  script_osvdb_id(151763);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc23838");
  script_xref(name:"IAVA", value:"2017-A-0042");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170208-asa");

  script_name(english:"Cisco ASA Clientless SSL VPN Functionality CIFS RCE (cisco-sa-20170208-asa)");
  script_summary(english:"Checks the ASA version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version and configuration, the Cisco
Adaptive Security Appliance (ASA) software running on the remote
device is affected by a heap overflow condition in the CIFS (Common
Internet Filesystem) code within the Clientless SSL VPN functionality
due to improper validation of user-supplied input. An authenticated,
remote attacker can exploit this, via a specially crafted URL, to
cause the device to reload or the execution of arbitrary code.

Note that only traffic directed to the affected system can be used to
exploit this issue, which affects systems configured in routed
firewall mode only and in single or multiple context mode. A valid TCP
connection is needed to perform the attack. Furthermore, the attacker
would need to have valid credentials to log in to the Clientless SSL
VPN portal. This vulnerability can be triggered by IPv4 or IPv6
traffic.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170208-asa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4f26697b");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvc23838");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20170208-asa.

Alternatively, as a workaround, it is possible to block an offending
URL using a webtype access list, which can be performed using the
following steps :

  1. Configure the webtype access list :

      access-list bugCSCvc23838 webtype deny url
      https://<asa_ip_address>/+webvpn+/CIFS_R/*
      access-list bugCSCvc23838 webtype permit url https://*
      access-list bugCSCvc23838 webtype permit url cifs://*

  2. Apply the access list in the group policy with the
     'filter value <webtype_acl_name>' command :

      group-policy Clientless attributes
       webvpn
        filter value bugCSCvc23838");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

asa = get_kb_item_or_exit('Host/Cisco/ASA');
model = get_kb_item_or_exit('Host/Cisco/ASA/model');

version = extract_asa_version(asa);
if (isnull(version)) audit(AUDIT_FN_FAIL, 'extract_asa_version');

if (
  model !~ '^55[0-9][0-9]($|[^0-9])' && # 5500 & 5500-X
  model !~ '^93[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^41[0-9][0-9]($|[^0-9])' && # Firepower ASA
  model !~ '^30[0-9][0-9]($|[^0-9])' && # ISA 3000
  model !~ '^(1000)?v$'                          # reported by ASAv
) audit(AUDIT_HOST_NOT, "an affected Cisco ASA product");

cbi = 'CSCvc23838';

if (version =~ "^7\.[0-2][^0-9]")
  fixed_ver = "9.1(7.13)";

else if (version =~ "^8\.[0-7][^0-9]")
  fixed_ver = "9.1(7.13)";

else if (version =~ "^9\.0[^0-9]" && check_asa_release(version:version, patched:"9.1(7.13)"))
  fixed_ver = "9.1(7.13)";

else if (version =~ "^9\.1[^0-9]" && check_asa_release(version:version, patched:"9.1(7.13)"))
  fixed_ver = "9.1(7.13)";

else if (version =~ "^9\.2[^0-9]")
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.3[^0-9]")
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.4[^0-9]" && check_asa_release(version:version, patched:"9.4(4)"))
  fixed_ver = "9.4(4)";

else if (version =~ "^9\.5[^0-9]")
  fixed_ver = "9.6(2.10)";

else if (version =~ "^9\.6[^0-9]" && check_asa_release(version:version, patched:"9.6(2.10)"))
  fixed_ver = "9.6(2.10)";

else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);

override = FALSE;
flag = FALSE;
anyconnect = FALSE;

# Cisco ASA configured with a Cisco AnyConnect Essential license
# is not affected by this vulnerability.
# License info can be gathered with show-version (ssh_get_info.nasl) saves this
show_ver = get_kb_item('Host/Cisco/show_ver');
if (!isnull(show_ver))
{
  if (preg(multiline:TRUE, pattern:"AnyConnect Essentials/s+:\s*Enabled", string:show_ver))
    anyconnect = TRUE;
}

if (anyconnect)
  audit(AUDIT_HOST_NOT, "affected because this Cisco ASA device has been configured with a Cisco AnyConnect Essential license.");

if (get_kb_item("Host/local_checks_enabled"))
{
  # Check that webvpn is enabled on at least one interface
  buf = cisco_command_kb_item("Host/Cisco/Config/show running-config webvpn", "show running-config webvpn");

  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:".*enable outside", string:buf))
    {
      # Check that the ssl-clientless option is configured
      buf2 = cisco_command_kb_item("Host/Cisco/Config/show running-config group-policy | include vpn-tunnel-protocol", "show running-config group-policy | include vpn-tunnel-protocol");
      if (check_cisco_result(buf2))
      {
        if (preg(multiline:TRUE, pattern:"vpn-tunnel-protocol.*ssl-clientless", string:buf2))
          flag = TRUE;
      }
    }
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the Clientless SSL VPN portal is not enabled");
}

if (flag || override)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_HOLE,
    override : override,
    version  : version,
    bug_id   : cbi,
    fix      : fixed_ver,
    cmds     : make_list("show running-config webvpn", "show running-config group-policy | include vpn-tunnel-protocol")
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "Cisco ASA software", version);
