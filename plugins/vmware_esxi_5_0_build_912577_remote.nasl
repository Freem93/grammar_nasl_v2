#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");

if (description)
{
  script_id(70885);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/09 15:53:03 $");

  script_cve_id(
    "CVE-2009-5029",
    "CVE-2009-5064",
    "CVE-2010-0830",
    "CVE-2010-4180",
    "CVE-2010-4252",
    "CVE-2011-0014",
    "CVE-2011-1089",
    "CVE-2011-3048",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4609",
    "CVE-2011-4619",
    "CVE-2012-0050",
    "CVE-2012-0864",
    "CVE-2012-3404",
    "CVE-2012-3405",
    "CVE-2012-3406",
    "CVE-2012-3480",
    "CVE-2013-1406",
    "CVE-2013-1659"
  );
  script_bugtraq_id(
    40063,
    45163,
    45164,
    46264,
    46740,
    50898,
    51281,
    51439,
    51563,
    52201,
    52830,
    54374,
    54982,
    57867,
    58115
  );
  script_osvdb_id(
    65077,
    69565,
    69657,
    70847,
    74278,
    74883,
    77508,
    78186,
    78187,
    78188,
    78189,
    78190,
    78316,
    78320,
    79705,
    80719,
    80822,
    84710,
    88150,
    88151,
    88152,
    90019,
    90554
  );
  script_xref(name:"VMSA", value:"2013-0002");
  script_xref(name:"VMSA", value:"2013-0003");
  script_xref(name:"VMSA", value:"2012-0013");
  script_xref(name:"VMSA", value:"2012-0018");

  script_name(english:"ESXi 5.0 < Build 912577 Multiple Vulnerabilities (remote check)");
  script_summary(english:"Checks the ESXi version and build number.");

  script_set_attribute(attribute:"synopsis", value:
"The remote VMware ESXi 5.0 host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote VMware ESXi 5.0 host is affected by Multiple
Vulnerabilities :

  - An integer overflow condition exists in the
    __tzfile_read() function in the glibc library. An
    unauthenticated, remote attacker can exploit this, via
    a crafted timezone (TZ) file, to cause a denial of
    service or the execution of arbitrary code.
    (CVE-2009-5029)

  - ldd in the glibc library is affected by a privilege
    escalation vulnerability due to the omission of certain
    LD_TRACE_LOADED_OBJECTS checks in a crafted executable
    file. Note that this vulnerability is disputed by the
    library vendor. (CVE-2009-5064)

  - A remote code execution vulnerability exists in the
    glibc library due to an integer signedness error in the
    elf_get_dynamic_info() function when the '--verify'
    option is used. A remote attacker can exploit this by
    using a crafted ELF program with a negative value for a
    certain d_tag structure member in the ELF header.
    (CVE-2010-0830)

  - A flaw exists in OpenSSL due to a failure to properly
    prevent modification of the ciphersuite in the session
    cache when SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG is
    enabled. A remote attacker can exploit this to force a
    downgrade to an unintended cipher by intercepting the
    network traffic to discover a session identifier.
    (CVE-2010-4180)

  - A flaw exists in OpenSSL due to a failure to properly
    validate the public parameters in the J-PAKE protocol
    when J-PAKE is enabled. A remote attacker can exploit
    this, by sending crafted values in each round of the
    protocol, to bypass the need for knowledge of the shared
    secret. (CVE-2010-4252)

  - A out-of-bounds memory error exists in OpenSSL that
    allows a remote attacker to cause a denial of service or
    possibly obtain sensitive information by using a
    malformed ClientHello handshake message. This is also
    known as the 'OCSP stapling vulnerability'.
    (CVE-2011-0014)

  - A flaw exists in the addmntent() function in the glibc
    library due to a failure to report the error status for
    failed attempts to write to the /etc/mtab file. A local
    attacker can exploit this to corrupt the file by using
    writes from a process with a small RLIMIT_FSIZE value.
    (CVE-2011-1089)

  - An flaw exists in the png_set_text_2() function in the
    file pngset.c in the libpng library due to a failure to
    properly allocate memory. An unauthenticated, remote
    attacker can exploit this, via a crafted text chunk in a
    PNG image file, to trigger a heap-based buffer overflow,
    resulting in denial of service or the execution of
    arbitrary code. (CVE-2011-3048)

  - A flaw exists in the DTLS implementation in OpenSSL due
    to performing a MAC check only if certain padding is
    valid. A remote attacker can exploit this, via a padding
    oracle attack, to recover the plaintext. (CVE-2011-4108)

  - A double-free error exists in OpenSSL when the
    X509_V_FLAG_POLICY_CHECK is enabled. A remote attacker
    can exploit this by triggering a policy check failure,
    resulting in an unspecified impact. (CVE-2011-4109)

  - A flaw exists in OpenSSL in the SSL 3.0 implementation
    due to improper initialization of data structures used
    for block cipher padding. A remote attacker can exploit
    this, by decrypting the padding data sent by an SSL
    peer, to obtain sensitive information. (CVE-2011-4576)

  - A denial of service vulnerability exists in OpenSSL when
    RFC 3779 support is enabled. A remote attacker can
    exploit this to cause an assertion failure, by using an
    X.509 certificate containing certificate extension data
    associated with IP address blocks or Autonomous System
    (AS) identifiers. (CVE-2011-4577)

  - A denial of service vulnerability exists in the RPC
    implementation in the glibc library due to a flaw in the
    svc_run() function. A remote attacker can exploit this,
    via large number of RPC connections, to exhaust CPU
    resources. (CVE-2011-4609)

  - A denial of service vulnerability exists in the Server
    Gated Cryptography (SGC) implementation in OpenSSL due
    to a failure to properly handle handshake restarts. A
    remote attacker can exploit this, via unspecified
    vectors, to exhaust CPU resources. (CVE-2011-4619)

  - An denial of service vulnerability exists in OpenSSL due
    to improper support of DTLS applications. A remote
    attacker can exploit this, via unspecified vectors
    related to an out-of-bounds read error. Note that this
    vulnerability exists because of an incorrect fix for
    CVE-2011-4108. (CVE-2012-0050)

  - A security bypass vulnerability exists in the glibc
    library due to an integer overflow condition in the
    vfprintf() function in file stdio-common/vfprintf.c. An
    attacker can exploit this, by using a large number of
    arguments, to bypass the FORTIFY_SOURCE protection
    mechanism, allowing format string attacks or writing to
    arbitrary memory. (CVE-2012-0864)

  - A denial of service vulnerability exists in the glibc
    library in the vfprintf() function in file
    stdio-common/vfprintf.c due to a failure to properly
    calculate a buffer length. An attacker can exploit this,
    via a format string that uses positional parameters and
    many format specifiers, to bypass the FORTIFY_SOURCE
    format-string protection mechanism, thus causing stack
    corruption and a crash. (CVE-2012-3404)

  - A denial of service vulnerability exists in the glibc
    library in the vfprintf() function in file
    stdio-common/vfprintf.c due to a failure to properly
    calculate a buffer length. An attacker can exploit this,
    via a format string with a large number of format
    specifiers, to bypass the FORTIFY_SOURCE format-string
    protection mechanism, thus triggering desynchronization
    within the buffer size handling, resulting in a
    segmentation fault and crash. (CVE-2012-3405)

  - A flaw exists in the glibc library in the vfprintf()
    function in file stdio-common/vfprintf.c due to a
    failure to properly restrict the use of the alloca()
    function when allocating the SPECS array. An attacker
    can exploit this, via a crafted format string using
    positional parameters and a large number of format
    specifiers, to bypass the FORTIFY_SOURCE format-string
    protection mechanism, thus triggering a denial of
    service or the possible execution of arbitrary code.
    (CVE-2012-3406)

  - A flaw exists in the glibc library due to multiple
    integer overflow conditions in the strtod(), strtof(),
    strtold(), strtod_l(), and other unspecified related
    functions. A local attacker can exploit these to trigger
    a stack-based buffer overflow, resulting in an
    application crash or the possible execution of arbitrary
    code. (CVE-2012-3480)

  - A privilege escalation vulnerability exists in the
    Virtual Machine Communication Interface (VMCI) due to a
    failure by control code to properly restrict memory
    allocation. A local attacker can exploit this, via
    unspecified vectors, to gain privileges. (CVE-2013-1406)

  - An error exists in the implementation of the Network
    File Copy (NFC) protocol. A man-in-the-middle attacker
    can exploit this, by modifying the client-server data
    stream, to cause a denial of service or the execution
    of arbitrary code. (CVE-2013-1659)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2013-0003.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0013.html");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2012-0018.html");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2033751");
  script_set_attribute(attribute:"see_also", value:"http://kb.vmware.com/kb/2033767");
  script_set_attribute(attribute:"solution", value:
"Apply patch ESXi500-201212101-SG according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:vmware:esxi:5.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vsphere_detect.nbin");
  script_require_keys("Host/VMware/version", "Host/VMware/release");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit("Host/VMware/version");
rel = get_kb_item_or_exit("Host/VMware/release");

if ("ESXi" >!< rel) audit(AUDIT_OS_NOT, "ESXi");
if ("VMware ESXi 5.0" >!< rel) audit(AUDIT_OS_NOT, "ESXi 5.0");

match = eregmatch(pattern:'^VMware ESXi.*build-([0-9]+)$', string:rel);
if (isnull(match)) exit(1, 'Failed to extract the ESXi build number.');

build = int(match[1]);
fixed_build = 912577;

if (build < fixed_build)
{
  if (report_verbosity > 0)
  {
    report = '\n  ESXi version    : ' + ver +
             '\n  Installed build : ' + build +
             '\n  Fixed build     : ' + fixed_build +
             '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host has "+ver+" build "+build+" and thus is not affected.");
