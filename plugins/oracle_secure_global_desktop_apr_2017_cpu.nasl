#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99930);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/05/04 13:21:27 $");

  script_cve_id(
    "CVE-2013-1982",
    "CVE-2013-1983",
    "CVE-2013-1984",
    "CVE-2013-1985",
    "CVE-2013-1986",
    "CVE-2013-1987",
    "CVE-2013-1995",
    "CVE-2013-1998",
    "CVE-2013-2002",
    "CVE-2013-2003",
    "CVE-2013-2005",
    "CVE-2016-0762",
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-3739",
    "CVE-2016-4802",
    "CVE-2016-5018",
    "CVE-2016-5407",
    "CVE-2016-5419",
    "CVE-2016-5420",
    "CVE-2016-5421",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6306",
    "CVE-2016-6307",
    "CVE-2016-6308",
    "CVE-2016-6794",
    "CVE-2016-6796",
    "CVE-2016-6797",
    "CVE-2016-6816",
    "CVE-2016-6817",
    "CVE-2016-7055",
    "CVE-2016-8615",
    "CVE-2016-8616",
    "CVE-2016-8617",
    "CVE-2016-8618",
    "CVE-2016-8619",
    "CVE-2016-8620",
    "CVE-2016-8621",
    "CVE-2016-8622",
    "CVE-2016-8623",
    "CVE-2016-8624",
    "CVE-2016-8625",
    "CVE-2016-8735",
    "CVE-2016-8743",
    "CVE-2017-3730",
    "CVE-2017-3731",
    "CVE-2017-3732"
  );
  script_bugtraq_id(
    60121,
    60123,
    60124,
    60125,
    60126,
    60127,
    60128,
    60129,
    60132,
    60133,
    60137,
    90726,
    90997,
    91081,
    91319,
    92117,
    92292,
    92306,
    92309,
    92557,
    92628,
    92630,
    92982,
    92984,
    92987,
    93149,
    93150,
    93151,
    93152,
    93153,
    93368,
    93939,
    93940,
    93942,
    93943,
    93944,
    94094,
    94096,
    94097,
    94098,
    94100,
    94101,
    94102,
    94103,
    94105,
    94106,
    94107,
    94242,
    94461,
    94462,
    94463,
    95077,
    95812,
    95813,
    95814
  );
  script_osvdb_id(
    93647,
    93652,
    93654,
    93655,
    93660,
    93663,
    93671,
    93672,
    93674,
    93675,
    93676,
    138663,
    139172,
    139313,
    139471,
    142095,
    142492,
    142493,
    142494,
    143021,
    143259,
    143309,
    143387,
    143388,
    143389,
    143392,
    144680,
    144687,
    144688,
    144689,
    144690,
    145120,
    146348,
    146354,
    146355,
    146356,
    146357,
    146555,
    146565,
    146567,
    146568,
    146569,
    146570,
    146571,
    146572,
    146573,
    146574,
    146575,
    147021,
    147617,
    147618,
    147619,
    149054,
    151018,
    151019,
    151020
  );
  script_xref(name:"EDB-ID", value:"41783");
  script_xref(name:"IAVA", value:"2017-A-0117");

  script_name(english:"Oracle Secure Global Desktop Multiple Vulnerabilities (April 2017 CPU) (SWEET32)");
  script_summary(english:"Checks the version of Oracle Secure Global Desktop.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Secure Global Desktop installed on the remote
host is 4.71, 5.2, or 5.3 and is missing a security patch from the
April 2017 Critical Patch Update (CPU). It is, therefore, affected by
multiple vulnerabilities :

  - An integer overflow condition exists in the Window System
    (X11) subcomponent in multiple functions in X.Org libExt
    due to improper validation of user-supplied input when
    calculating the amount of memory required to handle
    return data. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code. Note that this issue
    only affects version 4.71. (CVE-2013-1982)

  - An integer overflow condition exists in X.Org libXfixes
    in the XFixesGetCursorImage() function when handling
    large cursor dimensions or name lengths due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2013-1983)

  - An integer overflow condition exists within multiple
    functions in X.Org libXi due to improper validation of
    user-supplied input when calculating the amount of
    memory needed to handle return data. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2013-1984)

  - An integer overflow condition exists in X.Org
    libXinerama in the XineramaQueryScreens() function due
    to improper validation of user-supplied input when
    calculating the amount of memory needed to handle return
    data. An unauthenticated, remote attacker can exploit
    this to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2013-1985)

  - An integer overflow condition exists in multiple
    functions in X.Org libXrandr due to improper validation
    of user-supplied input when calculating the amount of
    memory needed to handle return data. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2013-1986)

  - An integer overflow condition exists in multiple
    functions in X.Org libXrender due to improper validation
    of user-supplied input when calculating the amount of
    memory needed to handle return data. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2013-1987)

  - An overflow condition exists in X.Org libXi in the
    XListInputDevices() function, related to an unexpected
    sign extension, due to improper checking of the amount
    of memory needed to handle returned data when converting
    smaller integer types to larger ones. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2013-1995)

  - An overflow condition exists within multiple functions
    in X.Org LibXi due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted length or
    index, to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2013-1998)

  - An overflow condition exists in X.Org LibXt in the
    _XtResourceConfigurationEH() function due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted length or index, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2013-2002)

  - An integer overflow condition exists in X.Org libXcursor
    in the  _XcursorFileHeaderCreate() function due to
    improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted file, to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2013-2003)

  - An uninitialized pointer flaw exists within multiple
    functions in X.Org LibXt due to a failure to check for
    proper initialization of pointers. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in a denial of service condition or the
    possible execution of arbitrary code. (CVE-2013-2005)

  - A flaw exists in the Application Server subcomponent
    (Apache Tomcat) due to a failure to process passwords
    when they are paired with non-existent usernames. An
    authenticated, remote attacker can exploit this, via a
    timing attack, to enumerate user account names.
    (CVE-2016-0762)

  - Multiple integer overflow conditions exist in s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit these to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the DTLS
    implementation due to a failure to properly restrict the
    lifetime of queue entries associated with unused
    out-of-order messages. An unauthenticated, remote
    attacker can exploit this, by maintaining multiple
    crafted DTLS sessions simultaneously, to exhaust memory.
    (CVE-2016-2179)

  - An out-of-bounds read error exists in the X.509 Public
    Key Infrastructure Time-Stamp Protocol (TSP)
    implementation. An unauthenticated, remote attacker can
    exploit this, via a crafted time-stamp file that is
    mishandled by the 'openssl ts' command, to cause a
    denial of service or to disclose sensitive information.
    (CVE-2016-2180)

  - A denial of service vulnerability exists in the
    Anti-Replay feature in the DTLS implementation due to
    improper handling of epoch sequence numbers in records.
    An unauthenticated, remote attacker can exploit this,
    via spoofed DTLS records, to cause legitimate packets to
    be dropped. (CVE-2016-2181)

  - An overflow condition exists in the BN_bn2dec() function
    in bn_print.c due to improper validation of
    user-supplied input when handling BIGNUM values. An
    unauthenticated, remote attacker can exploit this to
    crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - A flaw exists in the Core subcomponent, specifically in
    the libcurl library, due to improper validation of TLS
    certificates. An authenticated, remote attacker with the
    ability to intercept network traffic can exploit this
    issue to disclose or manipulate transmitted data by
    spoofing the TLS/SSL server using a certificate that
    appears valid. Note that this issue only affects
    versions 5.2 and 5.3. (CVE-2016-3739)

  - A flaw exists in cURL and libcurl when loading dynamic
    link library (DLL) files security.dll, secur32.dll, or
    ws2_32.dll due searching an insecure path which may not
    be trusted or under user control. A local attacker can
    exploit this, via a Trojan DLL file placed in the search
    path, to execute arbitrary code with the privileges of
    the user running the program. (CVE-2016-4802)

  - A security bypass vulnerability exists in Apache Tomcat
    due to an unspecified flaw related to web applications.
    A local attacker can exploit this, via a utility method
    that is available to web applications, to bypass a
    configured SecurityManager. (CVE-2016-5018)

  - An out-of-bounds access error exists in the Window
    System (X11) subcomponent, specifically in the
    XvQueryAdaptors() function in file Xv.c, when handling
    server responses. An authenticated, remote attacker can
    exploit this to impact confidentiality, integrity, and
    availability. (CVE-2016-5407)

  - A use-after-free error exists in cURL and libcurl within
    file lib/vtls/vtls.c due to the program attempting to
    resume TLS sessions even if the client certificate
    fails. An unauthenticated, remote attacker can exploit
    this to bypass validation mechanisms, allowing the
    attacker to possibly control which connection is used.
    (CVE-2016-5419)

  - A flaw exists in cURL and libcurl in the
    Curl_ssl_config_matches() function within file
    lib/vtls/vtls.c due to the program reusing TLS
    connections with different client certificates. An
    unauthenticated, remote attacker can exploit this to
    disclose sensitive cross-realm information.
    (CVE-2016-5420)

  - A use-after-free error exists in cURL and libcurl in
    in the close_all_connections() function within file
    lib/multi.c due to connection pointers not being
    properly cleared. An unauthenticated, remote attacker
    can exploit this to have an unspecified impact on
    confidentiality, integrity, and availability.
    (CVE-2016-5421)

  - A flaw exists in the tls_decrypt_ticket() function
    in t1_lib.c due to improper handling of ticket HMAC
    digests. An unauthenticated, remote attacker can exploit
    this, via a ticket that is too short, to crash the
    process, resulting in a denial of service.
    (CVE-2016-6302)

  - An integer overflow condition exists in the
    MDC2_Update() function in mdc2dgst.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6303)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - A flaw exists in the SSL_peek() function in
    rec_layer_s3.c due to improper handling of empty
    records. An unauthenticated, remote attacker can exploit
    this, by triggering a zero-length record in an SSL_peek
    call, to cause an infinite loop, resulting in a denial
    of service condition. (CVE-2016-6305)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)

  - A denial of service vulnerability exists in the
    state-machine implementation due to a failure to check
    for an excessive length before allocating memory. An
    unauthenticated, remote attacker can exploit this, via a
    crafted TLS message, to exhaust memory resources.
    (CVE-2016-6307)

  - A denial of service vulnerability exists in the DTLS
    implementation due to improper handling of excessively
    long DTLS messages. An unauthenticated, remote attacker
    can exploit this, via a crafted DTLS message, to exhaust
    available memory resources. (CVE-2016-6308)

  - A flaw exists in Apache Tomcat within SecurityManager
    due to improper restriction of access to system
    properties by the configuration files system property
    replacement feature. A local attacker can exploit this,
    via a crafted web application, to bypass SecurityManager
    restrictions and disclose system properties.
    (CVE-2016-6794)

  - A flaw exists in Apache Tomcat that allows a local
    attacker to bypass a configured SecurityManager by
    changing the configuration parameters for the JSP
    Servlet. (CVE-2016-6796)

  - A flaw exists in Apache Tomcat due to a failure to limit
    web application access to global JNDI resources. A local
    attacker can exploit this to gain unauthorized access to
    resources. (CVE-2016-6797)

  - A flaw exists in Apache Tomcat when handling request
    lines containing certain invalid characters. An
    unauthenticated, remote attacker can exploit this to
    conduct HTTP response splitting attacks by injecting
    additional headers into responses. (CVE-2016-6816)

  - An infinite loop condition exists in Apache Tomcat in
    the HTTP/2 parser when handling overly large headers. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to cause a denial of service
    condition. (CVE-2016-6817)

  - A carry propagation error exists in the
    Broadwell-specific Montgomery multiplication procedure
    when handling input lengths divisible by but longer than
    256 bits. This can result in transient authentication
    and key negotiation failures or reproducible erroneous
    outcomes of public-key operations with specially crafted
    input. A man-in-the-middle attacker can possibly exploit
    this issue to compromise ECDH key negotiations that
    utilize Brainpool P-512 curves. (CVE-2016-7055)

  - A flaw exists in cURL in the Curl_cookie_init() function
    within file lib/cookie.c when handling cookies. An
    unauthenticated, remote attacker can exploit this to
    inject new cookies for arbitrary domains.
    (CVE-2016-8615)

  - A flaw exists in cURL in the ConnectionExists() function
    within file lib/url.c when checking credentials supplied
    for reused connections due to the comparison being
    case-insensitive. An unauthenticated, remote attacker
    can exploit this to authenticate without knowing the
    proper case of the username and password.
    (CVE-2016-8616)

  - An integer overflow condition exists in cURL in the
    base64_encode() function within file lib/base64.c due to
    improper validation of certain input. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2016-8617)

  - A denial of service vulnerability exists in cURL in the
    alloc_addbyter() function within file lib/mprintf.c due
    to improper validation of overly long input when it is
    supplied to the curl_maprintf() API method. An
    unauthenticated, remote attacker can exploit this to
    free already freed memory and thereby crash the program.
    (CVE-2016-8618)

  - A double-free error exists in cURL in the read_data()
    function within file lib/security.c when handling
    Kerberos authentication. An unauthenticated, remote
    attacker can exploit this to free already freed memory,
    resulting in an unspecified impact on confidentiality,
    integrity, and availability. (CVE-2016-8619)

  - An out-of-bounds access error exists in cURL in file
    tool_urlglob.c within the globbing feature. An
    unauthenticated, remote attacker can exploit this to
    disclose memory contents or execute arbitrary code.
    (CVE-2016-8620)

  - An out-of-bounds error exists in cURL in the parsedate()
    function within file lib/parsedate.c when handling
    dates. An unauthenticated, remote attacker can exploit
    this to disclose memory contents or cause a denial of
    service condition. (CVE-2016-8621)

  - An integer truncation error exists in cURL in the
    curl_easy_unescape() function within file lib/escape.c
    when handling overly large URLs. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2016-8622)

  - A use-after-free error exists in cURL within file
    lib/cookie.c when handling shared cookies. An
    unauthenticated, remote attacker can exploit this to
    disclose memory contents. (CVE-2016-8623)

  - A flaw exists in cURL in the parseurlandfillconn()
    function within file lib/url.c when parsing the
    authority component of a URL with the host name part
    ending in a '#' character. An unauthenticated, remote
    attacker can exploit this to establish a connection to
    a different host than intended. (CVE-2016-8624)

  - A flaw exists in cURL within International Domain Names
    (IDNA) handling when translating domain names to puny
    code for DNS resolving due to using the outdated IDNA
    2003 standard instead of the IDNA 2008 standard, which
    can result in incorrect translation of a domain name.
    An unauthenticated, remote attacker can exploit this to
    cause network traffic to be redirected to a different
    host than intended. (CVE-2016-8625)

  - A flaw exists in Apache Tomcat within the
    catalina/mbeans/JmxRemoteLifecycleListener.java class
    that is triggered during the deserialization of Java
    objects. An unauthenticated, remote attacker can exploit
    this to execute arbitrary code. (CVE-2016-8735)

  - A flaw exists in the Web Server component (Apache HTTP
    Server) when handling whitespace patterns in User-Agent
    headers. An authenticated, remote attacker can exploit
    this, via a specially crafted User-Agent header, to
    cause incorrect processing of sequences of requests,
    resulting in incorrectly interpreting responses,
    polluting the cache, or disclosing content from one
    request to a second downstream user-agent.
    (CVE-2016-8743)

  - A NULL pointer dereference flaw exists within file
    ssl/statem/statem_clnt.c when handling parameters for
    the DHE or ECDHE key exchanges. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    parameters, to cause a denial of service condition.
    (CVE-2017-3730)

  - A out-of-bounds read error exists exists in the Core
    subcomponent, specifically in OpenSSL, when handling
    packets using the CHACHA20/POLY1305 or RC4-MD5 ciphers.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted truncated packets, to cause a
    denial of service condition. (CVE-2017-3731)

  - A carry propagating error exists in the x86_64
    Montgomery squaring implementation that may cause the
    BN_mod_exp() function to produce incorrect results. An
    unauthenticated, remote attacker with sufficient
    resources can exploit this to obtain sensitive
    information regarding private keys. Note that this issue
    is very similar to CVE-2015-3193. Moreover, the attacker
    would additionally need online access to an unpatched
    system using the target private key in a scenario with
    persistent DH parameters and a private key that is
    shared between multiple clients. For example, this can
    occur by default in OpenSSL DHE based SSL/TLS cipher
    suites. (CVE-2017-3732)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # http://www.oracle.com/technetwork/security-advisory/cpuapr2017-3236618.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?623d2c22");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2017 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:virtualization_secure_global_desktop");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("oracle_secure_global_desktop_installed.nbin");
  script_require_keys("Host/Oracle_Secure_Global_Desktop/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = "Oracle Secure Global Desktop";
version = get_kb_item_or_exit("Host/Oracle_Secure_Global_Desktop/Version");

# this check is for Oracle Secure Global Desktop packages
# built for Linux platform
uname = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname) audit(AUDIT_OS_NOT, "Linux");

fix_required = NULL;

if (version =~ "^5\.30($|\.)") fix_required = 'Patch_53p1';
else if (version =~ "^5\.20($|\.)") fix_required = 'Patch_52p8';
else if (version =~ "^4\.71($|\.)") fix_required = 'Patch_471p11';

if (isnull(fix_required)) audit(AUDIT_INST_VER_NOT_VULN, "Oracle Secure Global Desktop", version);

patches = get_kb_list("Host/Oracle_Secure_Global_Desktop/Patches");

patched = FALSE;
foreach patch (patches)
{
  if (patch == fix_required)
  {
    patched = TRUE;
    break;
  }
}

if (patched) audit(AUDIT_INST_VER_NOT_VULN, app, version + ' (with ' + fix_required + ')');

report = '\n  Installed version : ' + version +
           '\n  Patch required    : ' + fix_required +
           '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_HOLE);
