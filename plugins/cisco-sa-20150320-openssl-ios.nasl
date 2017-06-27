#TRUSTED 9a0367b81b019ad023ee6701f6adb41344840c0783edfc56fd8e2abb7be127553e40b762ae3bfb68b0e0dd03b5409d18445fadf0d0aa41ed495b25b1e9d5ddf15e37cdf1ce953e352c3f8ef39554c8b1705aa6b8734e8a9b9c058fa51365ee782ce42c19d87d387087ae5331389d8bd5564d042d480a26d38eaf4062f54b12386db186b993e22be9cbf548f3482805e1b509ef220e6d2a3db5e0278a0408111151a94d3e9ea5d0736e6ecb6e6e598bb8beb9ad884b158b748148605871a1dfd59dad8ac7a74b6695f13ec2969ec9103a258f6192f87a890d62ea4d98a32f58d22a503674945bd179610c597a3122baa8502caa3445a65cb47ac83e9bdb140163d3d114243cd74fe5797690ebfe72b7b9e8ce57eca68fb8fff0e608b9d88e19aeac74d9d404d4fa6c740af50d3213ad925e89478e4af04ff47419c16058e686779358d17583ae431a18b4e8d1b03f54a07dbd8441ce56324b3e06d677fc1e0b1cbd6b4268dbf96382dabd147f36754e7835674ee5183ab38d0b6cda36857d5afdeb3c1b76d0d869508a98347c1df09ad4146ff77cdf10d7a55b3645350dd139086543f2787e589990ab6822c08757de55a0ce20e593b7eebe2114115a4d0df0ba64cda0dce907869c3e664610f0286670c72099131e10e9600bbb6d436c7ceb6cf0507d2239c7ddff0309dabc5c141c0c25fa52043100e02d2c92f4329d09f608
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90525);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2016/04/14");

  script_cve_id(
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0287",
    "CVE-2015-0288",
    "CVE-2015-0289",
    "CVE-2015-0292",
    "CVE-2015-0293"
  );
  script_bugtraq_id(
    73225,
    73227,
    73228,
    73231,
    73232,
    73237,
    73239
  );
  script_osvdb_id(
    118817,
    119328,
    119743,
    119755,
    119756,
    119757,
    119761
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCut46130");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150320-openssl");

  script_name(english:"Cisco IOS Multiple OpenSSL Vulnerabilities (CSCut46130)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS device is missing a vendor-supplied security
patch and has an IOS service configured to use TLS or SSL. It is,
therefore, affected by the following vulnerabilities in the bundled
OpenSSL library :

  - A use-after-free condition exists in the
    d2i_ECPrivateKey() function due to improper processing
    of malformed EC private key files during import. A
    remote attacker can exploit this to dereference or free
    already freed memory, resulting in a denial of service
    or other unspecified impact. (CVE-2015-0209)

  - An invalid read error exists in the ASN1_TYPE_cmp()
    function due to improperly performed boolean-type
    comparisons. A remote attacker can exploit this, via a
    crafted X.509 certificate to an endpoint that uses the
    certificate-verification feature, to cause an invalid
    read operation, resulting in a denial of service.
    (CVE-2015-0286)

  - A flaw exists in the ASN1_item_ex_d2i() function due to
    a failure to reinitialize 'CHOICE' and 'ADB' data
    structures when reusing a structure in ASN.1 parsing.
    This allows a remote attacker to cause an invalid write
    operation and memory corruption, resulting in a denial
    of service. (CVE-2015-0287)

  - A NULL pointer dereference flaw exists in the
    X509_to_X509_REQ() function due to improper processing
    of certificate keys. This allows a remote attacker, via
    a crafted X.509 certificate, to cause a denial of
    service. (CVE-2015-0288)

  - A NULL pointer dereference flaw exists in the PKCS#7
    parsing code due to incorrect handling of missing outer
    ContentInfo. This allows a remote attacker, using an
    application that processes arbitrary PKCS#7 data and
    providing malformed data with ASN.1 encoding, to cause
    a denial of service. (CVE-2015-0289)

  - An integer underflow condition exists in the
    EVP_DecodeUpdate() function due to improper validation
    of base64 encoded input when decoding. This allows a
    remote attacker, using maliciously crafted base64 data,
    to cause a segmentation fault or memory corruption,
    resulting in a denial of service or possibly the
    execution of arbitrary code. (CVE-2015-0292)

  - A flaw exists in servers that both support SSLv2 and
    enable export cipher suites due to improper
    implementation of SSLv2. A remote attacker can exploit
    this, via a crafted CLIENT-MASTER-KEY message, to cause
    a denial of service. (CVE-2015-0293)");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150320-openssl
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2beef118");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCut46130");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20150319.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut46130.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

##
# Examines the output of show running config all for known SSL
# utilizing IOS features.
#
# @remark 'override' in the return value signals that the scan
#         was not provided sufficient credentials to check for
#         the related configurations. 'flag' signals whether or
#         not the configuration examined appears to be using SSL
#
# @return always an array like:
# {
#   'override' : (TRUE|FALSE),
#   'flag'     : (TRUE|FALSE)
# }
##
function ios_using_openssl()
{
  local_var res, buf;
  res = make_array(
    'override',  TRUE,
    'flag',      TRUE
  );

  # Signal we need local checks
  if (!get_kb_item("Host/local_checks_enabled"))
    return res;

  buf = cisco_command_kb_item(
    "Host/Cisco/Config/show_running-config_all",
    "show running-config all"
  );

  # Privilege escalation required
  if (cisco_needs_enable(buf))
    return res;

  res['flag'] = FALSE;

  # Check to make sure no errors in command output
  if(!check_cisco_result(buf))
    return res;

  # All good check for various SSL services
  res['override'] = FALSE;

   # Web UI HTTPS
  if (preg(string:buf, pattern:"^ip http secure-server", multiline:TRUE))
    res['flag'] = TRUE;
  # HTTPS client feature / Voice-XML HTTPS client
  else if (preg(string:buf, pattern:"^(ip )?http client secure-", multiline:TRUE))
    res['flag'] = TRUE;
  # CNS feature
  else if (preg(string:buf, pattern:"^cns (config|exec|event) .* encrypt", multiline:TRUE))
    res['flag'] = TRUE;
  # CMTS billing feature
  else if (preg(string:buf, pattern:"^cable metering .* secure", multiline:TRUE))
    res['flag'] = TRUE;
  # SSL VPN
  else if (
    cisco_check_sections(
      config        : buf,
      section_regex : "^webvpn gateway ",
      config_regex  :'^\\s*inservice'
     )
  ) res['flag'] = TRUE;
  # Settlement for Packet Telephony feature
  else if (
    cisco_check_sections(
      config        : buf,
      section_regex : "^settlement ",
      config_regex  : make_list('^\\s*url https:', '^\\s*no shutdown')
    )
  ) res['flag'] = TRUE;

  return res;
}

##
# Main check logic
##

# Look for known affected versions
affected = make_list(
'12.2(58)EX',    '12.2(58)EY',    '12.2(58)EY1',   '12.2(58)EY2',   '12.2(58)EZ',    '12.2(60)EZ',    '12.2(60)EZ1',
'12.2(60)EZ2',   '12.2(60)EZ3',   '12.2(60)EZ4',   '12.2(60)EZ5',   '12.2(60)EZ6',   '12.2(60)EZ7',   '12.2(60)EZ8',
'12.2(58)SE',    '12.2(58)SE1',   '12.2(58)SE2',   '12.2(54)SG',    '12.2(54)SG1',   '12.2(54)WO',    '12.2(54)XO',
'12.4(22)GC1',   '12.4(24)GC1',   '12.4(24)GC3',   '12.4(24)GC3a',  '12.4(24)GC4',   '12.4(24)GC5',   '12.4(22)MD',
'12.4(22)MD1',   '12.4(22)MD2',   '12.4(24)MD',    '12.4(24)MD1',   '12.4(24)MD2',   '12.4(24)MD3',   '12.4(24)MD4',
'12.4(24)MD5',   '12.4(24)MD6',   '12.4(24)MD7',   '12.4(22)MDA',   '12.4(22)MDA1',  '12.4(22)MDA2',  '12.4(22)MDA3',
'12.4(22)MDA4',  '12.4(22)MDA5',  '12.4(22)MDA6',  '12.4(24)MDA1',  '12.4(24)MDA10', '12.4(24)MDA11', '12.4(24)MDA12',
'12.4(24)MDA13', '12.4(24)MDA2',  '12.4(24)MDA3',  '12.4(24)MDA4',  '12.4(24)MDA5',  '12.4(24)MDA6',  '12.4(24)MDA7',
'12.4(24)MDA8',  '12.4(24)MDA9',  '12.4(24)MDB',   '12.4(24)MDB1',  '12.4(24)MDB10', '12.4(24)MDB11', '12.4(24)MDB12',
'12.4(24)MDB13', '12.4(24)MDB14', '12.4(24)MDB15', '12.4(24)MDB16', '12.4(24)MDB17', '12.4(24)MDB18', '12.4(24)MDB19',
'12.4(24)MDB3',  '12.4(24)MDB4',  '12.4(24)MDB5',  '12.4(24)MDB5a', '12.4(24)MDB6',  '12.4(24)MDB7',  '12.4(24)MDB8',
'12.4(24)MDB9',  '12.4(22)T',     '12.4(22)T1',    '12.4(22)T2',    '12.4(22)T3',    '12.4(22)T4',    '12.4(22)T5',
'12.4(24)T',     '12.4(24)T1',    '12.4(24)T2',    '12.4(24)T3',    '12.4(24)T3e',   '12.4(24)T3f',   '12.4(24)T4',
'12.4(24)T4a',   '12.4(24)T4b',   '12.4(24)T4c',   '12.4(24)T4d',   '12.4(24)T4e',   '12.4(24)T4f',   '12.4(24)T4l',
'12.4(24)T5',    '12.4(24)T6',    '12.4(24)T7',    '12.4(24)T8',    '12.4(22)XR1',   '12.4(22)XR10',  '12.4(22)XR11',
'12.4(22)XR12',  '12.4(22)XR2',   '12.4(22)XR3',   '12.4(22)XR4',   '12.4(22)XR5',   '12.4(22)XR6',   '12.4(22)XR7',
'12.4(22)XR8',   '12.4(22)XR9',   '12.4(22)YD',    '12.4(22)YD1',   '12.4(22)YD2',   '12.4(22)YD3',   '12.4(22)YD4',
'12.4(22)YE2',   '12.4(22)YE3',   '12.4(22)YE4',   '12.4(22)YE5',   '12.4(22)YE6',   '12.4(24)YE',    '12.4(24)YE1',
'12.4(24)YE2',   '12.4(24)YE3',   '12.4(24)YE3a',  '12.4(24)YE3b',  '12.4(24)YE3c',  '12.4(24)YE3d',  '12.4(24)YE3e',
'12.4(24)YE4',   '12.4(24)YE5',   '12.4(24)YE6',   '12.4(24)YE7',   '12.4(24)YG1',   '12.4(24)YG2',   '12.4(24)YG3',
'12.4(24)YG4',   '15.0(2)EB',     '15.0(2)EC',     '15.0(2)ED',     '15.0(2)ED1',    '15.0(2)EH',     '15.0(2)EJ',
'15.0(2)EJ1',    '15.0(2)EK',     '15.0(2)EK1',    '15.0(1)EX',     '15.0(2)EX',     '15.0(2)EX1',    '15.0(2)EX2',
'15.0(2)EX3',    '15.0(2)EX4',    '15.0(2)EX5',    '15.0(2)EX8',    '15.0(2a)EX5',   '15.0(1)EY',     '15.0(1)EY1',
'15.0(1)EY2',    '15.0(2)EY',     '15.0(2)EY1',    '15.0(2)EY2',    '15.0(2)EY3',    '15.0(2)EZ',     '15.0(1)M',
'15.0(1)M1',     '15.0(1)M10',    '15.0(1)M2',     '15.0(1)M3',     '15.0(1)M4',     '15.0(1)M5',     '15.0(1)M6',
'15.0(1)M7',     '15.0(1)M8',     '15.0(1)M9',     '15.0(1)MR',     '15.0(2)MR',     '15.0(1)S2',     '15.0(1)S5',
'15.0(1)S6',     '15.0(1)SE',     '15.0(1)SE1',    '15.0(1)SE2',    '15.0(1)SE3',    '15.0(2)SE',     '15.0(2)SE1',
'15.0(2)SE2',    '15.0(2)SE3',    '15.0(2)SE4',    '15.0(2)SE5',    '15.0(2)SE6',    '15.0(2)SE7',    '15.0(2)SG',
'15.0(2)SG1',    '15.0(2)SG10',   '15.0(2)SG2',    '15.0(2)SG3',    '15.0(2)SG4',    '15.0(2)SG5',    '15.0(2)SG6',
'15.0(2)SG7',    '15.0(2)SG8',    '15.0(2)SQD',    '15.0(2)SQD1',   '15.0(1)XA',     '15.0(1)XA1',    '15.0(1)XA2',
'15.0(1)XA3',    '15.0(1)XA4',    '15.0(1)XA5',    '15.0(1)XO',     '15.0(1)XO1',    '15.0(2)XO',     '15.1(2)EY',
'15.1(2)EY1a',   '15.1(2)EY2',    '15.1(2)EY2a',   '15.1(2)EY3',    '15.1(2)EY4',    '15.1(2)GC',     '15.1(2)GC1',
'15.1(2)GC2',    '15.1(4)GC',     '15.1(4)GC1',    '15.1(4)GC2',    '15.1(4)M',      '15.1(4)M1',     '15.1(4)M10',
'15.1(4)M2',     '15.1(4)M3',     '15.1(4)M3a',    '15.1(4)M4',     '15.1(4)M5',     '15.1(4)M6',     '15.1(4)M7',
'15.1(4)M8',     '15.1(4)M9',     '15.1(1)MR',     '15.1(1)MR1',    '15.1(1)MR2',    '15.1(1)MR3',    '15.1(1)MR4',
'15.1(3)MR',     '15.1(3)MRA',    '15.1(3)MRA1',   '15.1(3)MRA2',   '15.1(3)MRA3',   '15.1(3)MRA4',   '15.1(1)S',
'15.1(1)S1',     '15.1(1)S2',     '15.1(2)S',      '15.1(2)S1',     '15.1(2)S2',     '15.1(3)S',      '15.1(3)S0a',
'15.1(3)S1',     '15.1(3)S2',     '15.1(3)S3',     '15.1(3)S4',     '15.1(3)S5',     '15.1(3)S5a',    '15.1(3)S6',
'15.1(1)SG',     '15.1(1)SG1',    '15.1(1)SG2',    '15.1(2)SG',     '15.1(2)SG1',    '15.1(2)SG2',    '15.1(2)SG3',
'15.1(2)SG4',    '15.1(2)SG5',    '15.1(2)SG6',    '15.1(2)SNG',    '15.1(2)SNH',    '15.1(2)SNI',    '15.1(2)SNI1',
'15.1(3)SVB1',   '15.1(3)SVD',    '15.1(3)SVD1',   '15.1(3)SVD2',   '15.1(3)SVE',    '15.1(3)SVF',    '15.1(3)SVF1',
'15.1(3)SVF4a',  '15.1(1)SY',     '15.1(1)SY1',    '15.1(1)SY2',    '15.1(1)SY3',    '15.1(1)SY4',    '15.1(1)SY5',
'15.1(2)SY',     '15.1(2)SY1',    '15.1(2)SY2',    '15.1(2)SY3',    '15.1(2)SY4',    '15.1(2)SY4a',   '15.1(2)SY5',
'15.1(1)T',      '15.1(1)T1',     '15.1(1)T2',     '15.1(1)T3',     '15.1(1)T4',     '15.1(1)T5',     '15.1(2)T',
'15.1(2)T0a',    '15.1(2)T1',     '15.1(2)T2',     '15.1(2)T2a',    '15.1(2)T3',     '15.1(2)T4',     '15.1(2)T5',
'15.1(3)T',      '15.1(3)T1',     '15.1(3)T2',     '15.1(3)T3',     '15.1(3)T4',     '15.1(1)XB',     '15.2(1)E',
'15.2(1)E1',     '15.2(1)E2',     '15.2(1)E3',     '15.2(2)E',      '15.2(2)E1',     '15.2(2)E2',     '15.2(2a)E1',
'15.2(3)E',      '15.2(3)E1',     '15.2(3)E2',     '15.2(3a)E',     '15.2(2)EB',     '15.2(2)EB1',    '15.2(1)EY',
'15.2(2)EA1',    '15.2(2)EA2',    '15.2(3)EA',     '15.2(1)GC',     '15.2(1)GC1',    '15.2(1)GC2',    '15.2(2)GC',
'15.2(3)GC',     '15.2(3)GC1',    '15.2(4)GC',     '15.2(4)GC1',    '15.2(4)GC2',    '15.2(4)GC3',    '15.2(2)JA',
'15.2(2)JA1',    '15.2(4)JA',     '15.2(4)JA1',    '15.2(2)JAX',    '15.2(2)JAX1',   '15.2(2)JB',     '15.2(2)JB1',
'15.2(2)JB2',    '15.2(2)JB3',    '15.2(2)JB4',    '15.2(2)JB5',    '15.2(4)JB',     '15.2(4)JB1',    '15.2(4)JB2',
'15.2(4)JB3',    '15.2(4)JB3a',   '15.2(4)JB3b',   '15.2(4)JB3h',   '15.2(4)JB3s',   '15.2(4)JB4',    '15.2(4)JB5',
'15.2(4)JB5h',   '15.2(4)JB5m',   '15.2(4)JB50',   '15.2(4)JB6',    '15.2(4)JB7',    '15.2(2)JN1',    '15.2(2)JN2',
'15.2(4)JN',     '15.2(4)M',      '15.2(4)M1',     '15.2(4)M2',     '15.2(4)M3',     '15.2(4)M4',     '15.2(4)M5',
'15.2(4)M6',     '15.2(4)M6a',    '15.2(4)M7',     '15.2(4)M8',     '15.2(1)S',      '15.2(1)S1',     '15.2(1)S2',
'15.2(2)S',      '15.2(2)S0a',    '15.2(2)S0c',    '15.2(2)S1',     '15.2(2)S2',     '15.2(4)S',      '15.2(4)S1',
'15.2(4)S2',     '15.2(4)S3',     '15.2(4)S3a',    '15.2(4)S4',     '15.2(4)S4a',    '15.2(4)S5',     '15.2(4)S6',
'15.2(4)S7',     '15.2(2)SNG',    '15.2(2)SNH1',   '15.2(2)SNI',    '15.2(1)SY',     '15.2(1)SY0a',   '15.2(1)SY1',
'15.2(1)T',      '15.2(1)T1',     '15.2(1)T2',     '15.2(1)T3',     '15.2(1)T3a',    '15.2(1)T4',     '15.2(2)T',
'15.2(2)T1',     '15.2(2)T2',     '15.2(2)T3',     '15.2(2)T4',     '15.2(3)T',      '15.2(3)T1',     '15.2(3)T2',
'15.2(3)T3',     '15.2(3)T4',     '15.3(3)JA',     '15.3(3)JA1',    '15.3(3)JA1m',   '15.3(3)JA1n',   '15.3(3)JA4',
'15.3(3)JA77',   '15.3(3)JAA',    '15.3(3)JAB',    '15.3(3)JAX',    '15.3(3)JAX1',   '15.3(3)JAX2',   '15.3(3)JBB',
'15.3(3)JN1',    '15.3(3)JN2',    '15.3(3)JN3',    '15.3(3)JN4',    '15.3(3)JNB',    '15.3(3)JNB1',   '15.3(3)JNB2',
'15.3(3)M',      '15.3(3)M1',     '15.3(3)M2',     '15.3(3)M3',     '15.3(3)M4',     '15.3(3)M5',     '15.3(1)S',
'15.3(1)S1',     '15.3(1)S2',     '15.3(2)S',      '15.3(2)S0a',    '15.3(2)S1',     '15.3(2)S2',     '15.3(3)S',
'15.3(3)S1',     '15.3(3)S1a',    '15.3(3)S2',     '15.3(3)S3',     '15.3(3)S4',     '15.3(3)S5',     '15.3(3)S6',
'15.3(1)T',      '15.3(1)T1',     '15.3(1)T2',     '15.3(1)T3',     '15.3(1)T4',     '15.3(2)T',      '15.3(2)T1',
'15.3(2)T2',     '15.3(2)T3',     '15.3(2)T4',     '15.4(1)CG',     '15.4(1)CG1',    '15.4(2)CG',     '15.4(3)M',
'15.4(3)M1',     '15.4(3)M2',     '15.4(3)M3',     '15.4(1)S',      '15.4(1)S1',     '15.4(1)S2',     '15.4(1)S3',
'15.4(1)S4',     '15.4(2)S',      '15.4(2)S1',     '15.4(2)S2',     '15.4(2)S3',     '15.4(3)S',      '15.4(3)S1',
'15.4(3)S2',     '15.4(3)S3',     '15.4(1)T',      '15.4(1)T1',     '15.4(1)T2',     '15.4(1)T3',     '15.4(1)T4',
'15.4(2)T',      '15.4(2)T1',     '15.4(2)T2',     '15.4(2)T3',     '15.5(1)S',      '15.5(1)S1',     '15.5(1)S2',
'15.5(2)S',      '15.5(1)T',      '15.5(1)T1',     '15.5(1)T2',     '15.5(2)T'
);

flag = FALSE;
foreach afver (affected)
{
  if (ver == afver)
  {
    flag = TRUE;
    break;
  }
}

if (!flag)
  audit(AUDIT_INST_VER_NOT_VULN, "Cisco IOS", ver);

# Configuration check
sslcheck = ios_using_openssl();

if (!sslcheck['flag'] && !sslcheck['override'])
  audit(AUDIT_HOST_NOT, "affected because it does not appear as though any service utilizing the OpenSSL library is enabled");

# Override is shown regardless of verbosity
report = "";
if (report_verbosity > 0)
{
  order  = make_list('Cisco bug ID', 'Installed release');
  report = make_array(
    order[0], 'CSCut46130',
    order[1], ver
  );
  report = report_items_str(report_items:report, ordered_fields:order);
}

security_hole(port:0, extra:report+cisco_caveat(sslcheck['override']));
