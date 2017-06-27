#TRUSTED 52f19f43c10207127187a447710503d139a951d6334ad8705a4e1ae5e88e6cf74998a15d7602cef6c2423be3dede9a035193e1a855fe7ffb5076a281a56b73789a0652dd6ef8cc183e0dad5cf4e3d0c736a8d295a228f26d9392816985fd2dae96857fd76fcc794a3df47cdbfa296e24d76cb2633f9f05b549a39b4b490d3e4f5b6833e6733ae055cc31bbe040437a45dfaf8ec69084e5b7a995581b2fc46c7b657411ef02276ef2902e319d7c98340719bd4ff39d56436bf3a1999f04f80e3a0d38df9683825316e0568a6187f971f4db260aa798882e0c6adf630fd7a7fcf9a1892d20b5fce6c9eb02288712fdc42db195661fff704cb4db701d7b4e5a32823c18c4dd7c94f1b09d8de49cbd599c77117a883b6c89445fad93cb84a9e52f3c9c5e1f7cd1c927ae0f131298be0f45e1761e9753d96929e8d1a1f5dc7bed9c20b8dde04485692b89a34bcf22b7e652470cf4c0aa6c7f9a793a49f4468402d8ec17fee3f2c4f4a88437b45329625af99822592f1ca6e07dba57e494db2cbbe2ec36d80be8415bb3f58dba677ff5112803b9ecb020a420eec10cefffbb61a7c37fb09423ca95f06117841f84051aa5e08ce1a2be18e6095642fb6592043e388f92c46abd7ee7c18beae8bb276a3e955f7af2b140feaa4ac2bf3cdf495fb8b133ea5d4cce7019f109f171d448ba9f62498ae3623b0de0c3648e4bb7aceb443c06e9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88991);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/03/20");

  script_cve_id(
    "CVE-2010-5298",
    "CVE-2014-0076",
    "CVE-2014-0195",
    "CVE-2014-0198",
    "CVE-2014-0221",
    "CVE-2014-0224",
    "CVE-2014-3470",
    "CVE-2015-0292"
  );
  script_bugtraq_id(
    66363,
    66801,
    67193,
    67898,
    67899,
    67900,
    67901,
    73228
  );
  script_osvdb_id(
    104810,
    105763,
    106531,
    107729,
    107730,
    107731,
    107732,
    119743
  );
  script_xref(name:"CERT", value:"978508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22563");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22571");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22641");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22643");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup22663");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup23937");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup24057");
  script_xref(name:"CISCO-BUG-ID", value:"CSCup44235");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140605-openssl");

  script_name(english:"Cisco NX-OS OpenSSL Multiple Vulnerabilities");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco device is running a version of NX-OS software that
is affected by multiple vulnerabilities in the bundled OpenSSL
library :

  - An error exists in the function 'ssl3_read_bytes'
    that could allow data to be injected into other
    sessions or allow denial of service attacks. Note
    this issue is only exploitable if
    'SSL_MODE_RELEASE_BUFFERS' is enabled. (CVE-2010-5298)

  - An error exists related to the implementation of the
    Elliptic Curve Digital Signature Algorithm (ECDSA) that
    could allow nonce disclosure via the 'FLUSH+RELOAD'
    cache side-channel attack. (CVE-2014-0076)

  - A buffer overflow error exists related to invalid DTLS
    fragment handling that could lead to execution of
    arbitrary code. Note this issue only affects OpenSSL
    when used as a DTLS client or server. (CVE-2014-0195)

  - An error exists in the function 'do_ssl3_write' that
    could allow a NULL pointer to be dereferenced leading
    to denial of service attacks. Note this issue is
    exploitable only if 'SSL_MODE_RELEASE_BUFFERS' is
    enabled. (CVE-2014-0198)

  - An error exists related to DTLS handshake handling that
    could lead to denial of service attacks. Note this
    issue only affects OpenSSL when used as a DTLS client.
    (CVE-2014-0221)

  - An unspecified error exists that could allow an
    attacker to cause usage of weak keying material
    leading to simplified man-in-the-middle attacks.
    (CVE-2014-0224)

  - An unspecified error exists related to anonymous ECDH
    ciphersuites that could allow denial of service
    attacks. Note this issue only affects OpenSSL TLS
    clients. (CVE-2014-3470)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140605-openssl#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0d64ee0f");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20140605.txt");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.openssl.org/news/vulnerabilities.html");
  script_set_attribute(attribute:"see_also", value:"http://eprint.iacr.org/2014/140");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/06/05/earlyccs.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the Cisco
advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");
version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

# Only affects Nexus and MDS 9000 devices
if (device != 'Nexus' && device != 'MDS')
  audit(AUDIT_DEVICE_NOT_VULN, device);

local_checks_enabled = get_kb_item("Host/local_checks_enabled");

flag     = FALSE;
override = FALSE;
fix      = NULL;
cbid     = FALSE;

########################################
# Model 1k
########################################
if (model =~ "^1[0-9][0-9][0-9][vV]$")
{
  if (
    # Affected versions from bug report
    version == "5.2(1)SV3(1.0.1)"  ||
    version == "5.2(1)SP1(7.0.64)" ||
    # Affected versions from other SSL advisories
    version == "4.0(4)SV1(1)"    ||
    version == "4.0(4)SV1(2)"    ||
    version == "4.0(4)SV1(3)"    ||
    version == "4.0(4)SV1(3a)"   ||
    version == "4.0(4)SV1(3b)"   ||
    version == "4.0(4)SV1(3c)"   ||
    version == "4.0(4)SV1(3d)"   ||
    version == "4.2(1)SV1(4)"    ||
    version == "4.2(1)SV1(4a)"   ||
    version == "4.2(1)SV1(4b)"   ||
    version == "4.2(1)SV1(5.1)"  ||
    version == "4.2(1)SV1(5.1a)" ||
    version == "4.2(1)SV1(5.2)"  ||
    version == "4.2(1)SV1(5.2b)" ||
    version == "4.2(1)SV2(1.1)"  ||
    version == "4.2(1)SV2(1.1a)" ||
    version == "4.2(1)SV2(2.1)"  ||
    version == "4.2(1)SV2(2.1a)" ||
    version == "5.2(1)SM1(5.1)"
  ) flag = TRUE;

  if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS", version);

  fix  = "5.2(1)AJ(1.1) / 5.2(1)SV3(1.1)";
  cbid = "CSCup22641";

  if (local_checks_enabled)
  {
    flag = FALSE;
    buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config_all", "show running-config all");

    if (check_cisco_result(buf))
    {
      override = FALSE;

      if (preg(string:buf, pattern:"^feature fabric sshServer", multiline:TRUE, icase:TRUE))
        flag = TRUE;
      else if (preg(string:buf, pattern:'^\\s*protocol vmware-vim($|\r?\n)', multiline:TRUE))
        flag = TRUE;
      else if (
        preg(string:buf, pattern:"^feature http-server", multiline:TRUE, icase:TRUE) &&
        !preg(string:buf, pattern:'^http-server no https($|\r?\n)', multiline:TRUE, icase:TRUE) 
      ) flag = TRUE;
    }

    else if (cisco_needs_enable(buf))
    {
      flag     = TRUE;
      override = TRUE;
    }
  }
}
########################################
# Model 3k
########################################
else if (
  model == "3064X"    ||
  model == "3064-32T" ||
  model == "3064T"    ||
  model == "3016Q"    ||
  model == "3048"     ||
  model == "3132Q"    ||
  model == "3172PQ"   ||
  model == "3172TQ"
)
{
  if (
    # Affected versions from bug report
    version == "6.2(1)PP(18)"    ||
    version == "7.1(0)ZN(0.76)"  ||
    version == "7.2(0.1)PR(0.1)" ||
    # Affected versions from other SSL advisories
    version == "5.0(3)U1(1)"     ||
    version == "5.0(3)U1(1a)"    ||
    version == "5.0(3)U1(1b)"    ||
    version == "5.0(3)U1(1d)"    ||
    version == "5.0(3)U1(2)"     ||
    version == "5.0(3)U1(2a)"    ||
    version == "5.0(3)U2(1)"     ||
    version == "5.0(3)U2(2)"     ||
    version == "5.0(3)U2(2a)"    ||
    version == "5.0(3)U2(2b)"    ||
    version == "5.0(3)U2(2c)"    ||
    version == "5.0(3)U2(2d)"    ||
    version == "5.0(3)U3(1)"     ||
    version == "5.0(3)U3(2)"     ||
    version == "5.0(3)U3(2a)"    ||
    version == "5.0(3)U3(2b)"    ||
    version == "5.0(3)U4(1)"     ||
    version == "5.0(3)U5(1)"     ||
    version == "5.0(3)U5(1a)"    ||
    version == "5.0(3)U5(1b)"    ||
    version == "5.0(3)U5(1c)"    ||
    version == "5.0(3)U5(1d)"    ||
    version == "5.0(3)U5(1e)"    ||
    version == "5.0(3)U5(1f)"    ||
    version == "5.0(3)U5(1g)"    ||
    version == "5.0(3)U5(1h)"    ||
    version == "6.0(2)U1(1)"     ||
    version == "6.0(2)U1(1a)"    ||
    version == "6.0(2)U1(2)"     ||
    version == "6.0(2)U1(3)"     ||
    version == "6.0(2)U1(4)"     ||
    version == "6.0(2)U2(1)"     ||
    version == "6.0(2)U2(2)"     ||
    version == "6.0(2)U2(3)"     ||
    version == "6.0(2)U2(4)"     ||
    version == "6.0(2)U2(5)"     ||
    version == "6.0(2)U2(6)"     ||
    version == "6.0(2)U3(1)"     ||
    version == "6.0(2)U3(2)"     ||
    version == "6.0(2)U3(3)"     ||
    version == "6.0(2)U3(4)"     ||
    version == "6.0(2)U3(5)"  
  ) flag = TRUE;

  if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS", version);

  fix  = "6.0(2)A4(1) / 6.0(2)U4(1)";
  cbid = "CSCup44235";

  if (local_checks_enabled)
  {
    flag = FALSE;
    buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config_all", "show running-config all");

    if (check_cisco_result(buf))
    {
      override = FALSE;

      if (preg(string:buf, pattern:"^feature fabric sshServer", multiline:TRUE, icase:TRUE))
        flag = TRUE;

      else if (preg(string:buf, pattern:'^\\s*transport type tls', multiline:TRUE, icase:TRUE))
        flag = TRUE;

      else if (
        preg(string:buf, pattern:"^feature nxapi", multiline:TRUE) &&
        preg(string:buf, pattern:"^nxapi https port", multiline:TRUE)
      ) flag = TRUE;

    }
    else if (cisco_needs_enable(buf))
    {
      flag     = TRUE;
      override = TRUE;
    }    
  }
}
########################################
# Model 5k / 6k
########################################
else if (model =~ "^[56][0-9][0-9][0-9][^0-9]+$")
{
  if (
    # Affected versions from bug report
    version == "6.0(2)N3(0.91)"  ||
    version == "7.2(0)VX(0.9)"   ||
    version == "7.2(0.1)PR(0.1)" ||
    version == "9.4(1)N1(6.8)"   ||
    # Affected versions from other SSL advisories
    version == "4.0(0)N1(1a)"  ||
    version == "4.0(0)N1(2)"   ||
    version == "4.0(0)N1(2a)"  ||
    version == "4.0(1a)N1(1)"  ||
    version == "4.0(1a)N1(1a)" ||
    version == "4.0(1a)N2(1)"  ||
    version == "4.0(1a)N2(1a)" ||
    version == "4.1(3)N1(1)"   ||
    version == "4.1(3)N1(1a)"  ||
    version == "4.1(3)N2(1)"   ||
    version == "4.1(3)N2(1a)"  ||
    version == "4.2(1)N1(1)"   ||
    version == "4.2(1)N2(1)"   ||
    version == "4.2(1)N2(1a)"  ||
    version == "5.0(2)N1(1)"   ||
    version == "5.0(3)N1(1c)"  ||
    version == "5.0(2)N2(1)"   ||
    version == "5.0(2)N2(1a)"  ||
    version == "5.0(3)N2(1)"   ||
    version == "5.0(3)N2(2)"   ||
    version == "5.0(3)N2(2a)"  ||
    version == "5.0(3)N2(2b)"  ||
    version == "5.1(3)N1(1)"   ||
    version == "5.1(3)N1(1a)"  ||
    version == "5.1(3)N2(1)"   ||
    version == "5.1(3)N2(1a)"  ||
    version == "5.1(3)N2(1b)"  ||
    version == "5.1(3)N2(1c)"  ||
    version == "5.2(1)N1(1)"   ||
    version == "5.2(1)N1(1a)"  ||
    version == "5.2(1)N1(1b)"  ||
    version == "5.2(1)N1(2)"   ||
    version == "5.2(1)N1(2a)"  ||
    version == "5.2(1)N1(3)"   ||
    version == "5.2(1)N1(4)"   ||
    version == "5.2(1)N1(5)"   ||
    version == "5.2(1)N1(6)"   ||
    version == "5.2(1)N1(7)"   ||
    version == "5.2(1)N1(8)"   ||
    version == "5.2(1)N1(8a)"  ||
    version == "6.0(2)N1(1)"   ||
    version == "6.0(2)N1(2)"   ||
    version == "6.0(2)N1(2a)"  ||
    version == "6.0(2)N2(1)"   ||
    version == "6.0(2)N2(1b)"  ||
    version == "6.0(2)N2(2)"   ||
    version == "6.0(2)N2(3)"   ||
    version == "6.0(2)N2(4)"   ||
    version == "6.0(2)N2(5)"   ||
    version == "7.0(0)N1(1)"   ||
    version == "7.0(1)N1(1)"   ||
    version == "7.0(2)N1(1)"   ||
    version == "7.0(3)N1(1)"
  ) flag = TRUE;

  if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS", version);

  fix  = "Contact vendor";
  cbid = "CSCup22365 and CSCup22663"; # These bugs are the same and cover 5k/6k

  if (local_checks_enabled)
  {
    flag = FALSE;
    buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config_all", "show running-config all");

    if (check_cisco_result(buf))
    {
      override = FALSE;

      if (
        preg(string:buf, pattern:"^feature http-server", multiline:TRUE, icase:TRUE) &&
        !preg(string:buf, pattern:'^http-server no https($|\r?\n)', multiline:TRUE, icase:TRUE)
      ) flag = TRUE;
      else if (
        preg(string:buf, pattern:"^feature nxapi", multiline:TRUE) &&
        preg(string:buf, pattern:"^nxapi https port", multiline:TRUE)
      ) flag = TRUE;
      else if (
        preg(string:buf, pattern:"^feature fabric access", multiline:TRUE) ||
        preg(string:buf, pattern:"^feature vmtracker", multiline:TRUE)
      ) flag = TRUE;
      else if (preg(string:buf, pattern:'^\\s*server protocol ldap [^\n] enable-ssl', multiline:TRUE))
        flag = TRUE;
      else if (preg(string:buf, pattern:'^\\s*transport type tls($|\r?\n)', multiline:TRUE))
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag     = TRUE;
      override = TRUE;
    }
  }
}
########################################
# Model 7k
########################################
else if (model =~ "^7[0-9][0-9][0-9]$" || device == "MDS")
{
  if (
    # Affected versions from bug report
    version == "5.2(8d)" ||
    version == "6.2(7)"  ||
    version == "6.2(8)"  ||
    version == "7.1(0)"  ||
    # Affected versions from other SSL advisories
    version == "4.1.(2)"  ||
    version == "4.1.(3)"  ||
    version == "4.1.(4)"  ||
    version == "4.1.(5)"  ||
    version == "4.2.(2a)" ||
    version == "4.1(2)"   ||
    version == "4.1(3)"   ||
    version == "4.1(4)"   ||
    version == "4.1(5)"   ||
    version == "4.2(2a)"  ||
    version == "4.2(3)"   ||
    version == "4.2(4)"   ||
    version == "4.2(6)"   ||
    version == "4.2(8)"   ||
    version == "5.0(2a)"  ||
    version == "5.0(3)"   ||
    version == "5.0(5)"   ||
    version == "5.1(1)"   ||
    version == "5.1(1a)"  ||
    version == "5.1(3)"   ||
    version == "5.1(4)"   ||
    version == "5.1(5)"   ||
    version == "5.1(6)"   ||
    version == "5.2(1)"   ||
    version == "5.2(3a)"  ||
    version == "5.2(4)"   ||
    version == "5.2(5)"   ||
    version == "5.2(7)"   ||
    version == "5.2(9)"   ||
    version == "6.0(1)"   ||
    version == "6.0(2)"   ||
    version == "6.0(3)"   ||
    version == "6.0(4)"   ||
    version == "6.1(1)"   ||
    version == "6.1(2)"   ||
    version == "6.1(3)"   ||
    version == "6.1(4)"   ||
    version == "6.1(4a)"  ||
    version == "6.2(2)"   ||
    version == "6.2(2a)"  ||
    version == "6.2(6)"   ||
    version == "6.2(6b)"  ||
    version == "6.2(8)"   ||
    version == "6.2(8a)"  ||
    version == "6.2(8b)"
  ) flag = TRUE;

  if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS", version);

  fix  = "Contact vendor";
  cbid = "CSCup22563";

  # Check to see if we can determine if SSL is enabled with LDAP
  if (local_checks_enabled)
  {
    flag = FALSE;
    buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config_all", "show running-config all");

    if (check_cisco_result(buf))
    {
      override = FALSE;
      
      if (
        preg(string:buf, pattern:"^feature ldap", multiline:TRUE) &&
        preg(string:buf, pattern:"^ldap-server .* enable-ssl", multiline:TRUE)
      ) flag = TRUE;
      else if (
        preg(string:buf, pattern:"^feature nxapi", multiline:TRUE) &&
        preg(string:buf, pattern:"^nxapi https port", multiline:TRUE)
      ) flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag     = TRUE;
      override = TRUE;
    }
  }
}

########################################
# Model 9k
########################################
else if (model =~ "^9[35][0-9][0-9]$" || model == "3164Q")
{
  if (
    # Affected versions from bug report
    version == "6.1(2)I2(2a)"    ||
    version == "6.2(8)IA(1)"     ||
    version == "7.2(0.1)VB(0.1)" ||
    # Affected versions from other SSL advisories
    version == "6.1(2)I2(1)"  ||
    version == "6.1(2)I2(2)"  ||
    version == "6.1(2)I2(2b)" ||
    version == "6.1(2)I2(3)"
  ) flag = TRUE;

  if (!flag) audit(AUDIT_INST_VER_NOT_VULN, "Cisco NX-OS", version);

  fix  = "6.1(2)I3(1) / 7.0(3)I1(1)";
  cbid = "CSCup24057";

  # Check to see if we can determine if SSL is enabled with LDAP
  if (local_checks_enabled)
  {
    flag = FALSE;
    buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config_all", "show running-config all");

    if (check_cisco_result(buf))
    {
      override = FALSE;

      if (
        preg(string:buf, pattern:"^feature ldap", multiline:TRUE) &&
        preg(string:buf, pattern:"^ldap-server .* enable-ssl", multiline:TRUE)
      ) flag = TRUE;
      else if (
        preg(string:buf, pattern:"^feature nxapi", multiline:TRUE) &&
        preg(string:buf, pattern:"^nxapi https port", multiline:TRUE)
      ) flag = TRUE;
    }
    else if (cisco_needs_enable(buf))
    {
      flag     = TRUE;
      override = TRUE;
    }
  }
}
else
  audit(AUDIT_DEVICE_NOT_VULN, device + ' ' + model);

if (!flag)
  audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");

if (report_verbosity > 0)
{
  report = 
    '\n  Cisco bug ID      : ' + cbid + 
    '\n  Model             : ' + device + ' ' + model +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';

  security_hole(port:0, extra:report + cisco_caveat(override));
}
else security_hole(port:0, extra: cisco_caveat(override));
