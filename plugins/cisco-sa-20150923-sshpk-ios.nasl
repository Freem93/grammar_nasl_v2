#TRUSTED 2d1fe357675dc31c614f2614bc4984832898f33378e95804ea5562c550b3a81080df63f1cc6e6550aede7b078989c7ae30950976bf0e2fd8367b9b43448eedae15f899b0106ef03aee746f9a37cb1717f7c019580d3c71955dca084c4819729b7133af3c7795735052383fab8e1840542b95ba907f23c8b749d201e1ae27d4cae75b2f731289753ca54de3c3d2bfe38e3dab9e59c83165b9173b9ff8530085fffca07551c90f0059b85b087f0675e2582f2d67d4e4e9b37d7af4626586cb5164d7041cb39f181943f840cec0f3c7979f80c558f318857d26a9cd2647e7699bdad2060620f28d10b7b9a64f5b534e89dd7887e32c428d49fdb5c94e1949b6e59dc8105b9df7fa59704831b1f7ca065daeac019152238b97f6391ac45b3e87d93832277be923e4dd7ddb0db5f1d360e5b3dc2b9f81507de87a5796d9e6f8859ed919c6e868e1ea4f21cbb86c00611a1d1acbc8292ae0b6ace69cf84fce5871f3c109ccc10a8d4ba41a59d8f594b0369af57e9f46703fff82f790b1d094ce614c9e253be6a4bcfce3228f87b815dc2ee563b5a7d6934b757bb16b44e7028ea66cca5c74156b33cad7940a58352b755c3745ad3e2df470b7e92e48cf91288d4ccca8547cb65e57d55b38361d3d50637513a1bea6a09b698f2fad87f3ea716fc966b1c4683219391100762465fb76ce422bb3688b3e5c406d41c020152f2f4a1728a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description){

  script_id(86249);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/03");

  script_cve_id("CVE-2015-6280");
  script_osvdb_id(127980);
  script_xref(name:"CISCO-BUG-ID", value:"CSCus73013");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-sshpk");

  script_name(english:"Cisco IOS SSHv2 RSA-Based User Authentication Bypass (CSCus73013)");
  script_summary(english:"Checks IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is missing a vendor-supplied security
patch, and is configured for SSHv2 RSA-based user authentication. It
is, therefore, affected by a flaw in the SSHv2 protocol implementation
of the public key authentication method. An unauthenticated, remote
attacker can exploit this, via a crafted private key, to bypass
authentication mechanisms. In order to exploit this vulnerability an
attacker must know a valid username configured for RSA-based user
authentication and the public key configured for that user.");
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-sshpk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?072064d6");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCus73013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

flag = 0;

if (ver =="15.2(1)SY") flag++;
if (ver =="15.2(1)SY0a") flag++;
if (ver =="15.2(2)E") flag++;
if (ver =="15.2(2)E1") flag++;
if (ver =="15.2(2)E2") flag++;
if (ver =="15.2(2)EA1") flag++;
if (ver =="15.2(2a)E1") flag++;
if (ver =="15.2(2a)E2") flag++;
if (ver =="15.2(3)E") flag++;
if (ver =="15.2(3)EA") flag++;
if (ver =="15.2(3a)E") flag++;
if (ver =="15.3(3)M1") flag++;
if (ver =="15.3(3)M2") flag++;
if (ver =="15.3(3)M3") flag++;
if (ver =="15.3(3)M4") flag++;
if (ver =="15.3(3)M5") flag++;
if (ver =="15.3(3)S") flag++;
if (ver =="15.3(3)S1") flag++;
if (ver =="15.3(3)S1a") flag++;
if (ver =="15.3(3)S2") flag++;
if (ver =="15.3(3)S3") flag++;
if (ver =="15.3(3)S4") flag++;
if (ver =="15.3(3)S5") flag++;
if (ver =="15.4(1)CG") flag++;
if (ver =="15.4(1)CG1") flag++;
if (ver =="15.4(1)S") flag++;
if (ver =="15.4(1)S1") flag++;
if (ver =="15.4(1)S2") flag++;
if (ver =="15.4(1)S3") flag++;
if (ver =="15.4(1)T") flag++;
if (ver =="15.4(1)T1") flag++;
if (ver =="15.4(1)T2") flag++;
if (ver =="15.4(1)T3") flag++;
if (ver =="15.4(2)CG") flag++;
if (ver =="15.4(2)S") flag++;
if (ver =="15.4(2)S1") flag++;
if (ver =="15.4(2)S2") flag++;
if (ver =="15.4(2)T") flag++;
if (ver =="15.4(2)T1") flag++;
if (ver =="15.4(2)T2") flag++;
if (ver =="15.4(3)M") flag++;
if (ver =="15.4(3)M1") flag++;
if (ver =="15.4(3)M2") flag++;
if (ver =="15.4(3)S") flag++;
if (ver =="15.4(3)S1") flag++;
if (ver =="15.4(3)S2") flag++;
if (ver =="15.5(1)S") flag++;
if (ver =="15.5(1)T") flag++;

if (get_kb_item("Host/local_checks_enabled") && flag)
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-begin-ip-ssh-pubkey-chain", "show running-config | begin ip ssh pubkey-chain");
  if (check_cisco_result(buf))
  {
    if (
      "ip ssh pubkey-chain" >< buf &&
      "username" >< buf
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCus73013' +
      '\n  Installed release : ' + ver +
      '\n';
    security_hole(port:0, extra:report + cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
