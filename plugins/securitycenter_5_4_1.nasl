#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96832);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/03/07 17:25:25 $");

  script_cve_id(
    "CVE-2016-7052",
    "CVE-2016-7103",
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7126",
    "CVE-2016-7127",
    "CVE-2016-7128",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7412",
    "CVE-2016-7413",
    "CVE-2016-7414",
    "CVE-2016-7415",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7418",
    "CVE-2016-9137"
  );
  script_bugtraq_id(
    92552,
    92564,
    92755,
    92756,
    92757,
    92758,
    92764,
    92767,
    92768,
    93004,
    93005,
    93006,
    93007,
    93008,
    93011,
    93022,
    93171,
    93577
  );
  script_osvdb_id(
    142096,
    143096,
    143100,
    143101,
    143102,
    143103,
    143104,
    143105,
    143106,
    143107,
    143108,
    143109,
    143110,
    143111,
    143112,
    143113,
    143114,
    143116,
    143117,
    143118,
    144259,
    144260,
    144261,
    144262,
    144263,
    144264,
    144268,
    144269,
    144270,
    144271,
    144273,
    144275,
    144287,
    144804,
    145227,
    145598,
    145599,
    145600,
    145601,
    145602,
    145603,
    145604,
    145605,
    145606,
    145607,
    145608,
    145609,
    145610,
    145611,
    146957,
    146975,
    147321,
    147910,
    147911,
    147912,
    147913,
    147914,
    147915,
    147916,
    147917,
    147918
  );

  script_name(english:"Tenable SecurityCenter < 5.4.1 Multiple Vulnerabilities (TNS-2016-19)");
  script_summary(english:"Checks the SecurityCenter version.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable SecurityCenter
application installed on the remote host is prior to 5.4.1. It is,
therefore, affected by multiple vulnerabilities :

  - A denial of service vulnerability exists in x509_vfy.c
    due to improper handling of certificate revocation lists
    (CRLs). An unauthenticated, remote attacker can exploit
    this, via a specially crafted CRL, to cause a NULL
    pointer dereference, resulting in a crash of the
    service. (CVE-2016-7052)

  - A cross-site scripting (XSS) vulnerability exists within
    the JQuery UI dialog() function due to improper
    validation of input to the 'closeText' parameter before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2016-7103)

  - A denial of service vulnerability exists in PHP within
    file ext/standard/var_unserializer.c due to improper
    handling of certain invalid objects. An unauthenticated,
    remote attacker can exploit this, via specially crafted
    serialized data that leads to a __destruct() or magic()
    function call, to cause a denial of service condition or
    potentially execute arbitrary code. (CVE-2016-7124)

  - A flaw exists in PHP in file ext/session/session.c when
    handling session names. An unauthenticated, remote
    attacker can exploit this to inject arbitrary data into
    sessions. (CVE-2016-7125)

  - An integer truncation error exists in PHP in the
    select_colors() function in file ext/gd/libgd/gd_topal.c
    when handling the number of colors. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in the execution of arbitrary
    code. (CVE-2016-7126)

  - An array-indexing error exists in PHP in the
    imagegammacorrect() function within file ext/gd/gd.c
    when handling negative gamma values. An unauthenticated,
    remote attacker can exploit this, by writing a NULL to
    an arbitrary memory location, to cause a crash or the
    execution of arbitrary code. (CVE-2016-7127)

  - A flaw exists in PHP in the exif_process_IFD_in_TIFF()
    function within file ext/exif/exif.c when handling TIFF
    image content. An unauthenticated, remote attacker can
    exploit this to disclose memory contents.
    (CVE-2016-7128)

  - A denial of service vulnerability exists in PHP in the
    php_wddx_process_data() function within file
    ext/wddx/wddx.c when deserializing invalid dateTime
    values. An unauthenticated, remote attacker can exploit
    this to cause a crash. (CVE-2016-7129)

  - A NULL pointer dereference flaw exists in PHP in the
    php_wddx_pop_element() function within file
    ext/wddx/wddx.c when handling Base64 binary values. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7130)

  - A NULL pointer dereference flaw exists in PHP in the
    php_wddx_deserialize_ex() function within file
    ext/wddx/wddx.c when handling invalid XML content. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (CVE-2016-7131)

  - A NULL pointer dereference flaw exists in PHP in the
    php_wddx_pop_element() function within file
    ext/wddx/wddx.c. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (CVE-2016-7132)

  - A buffer overflow condition exists in PHP in file
    ext/mysqlnd/mysqlnd_wireprotocol.c within the
    php_mysqlnd_rowp_read_text_protocol_aux() function when
    handling the BIT field. An unauthenticated, remote
    attacker can exploit this to cause a heap-based buffer
    overflow, resulting in a crash or the execution of
    arbitrary code. (CVE-2016-7412)

  - A use-after-free error exists in PHP in the
    wddx_stack_destroy() function within file
    ext/wddx/wddx.c when deserializing recordset elements.
    An unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (CVE-2016-7413)

  - An out-of-bounds access error exists in PHP in the
    phar_parse_zipfile() function within file ext/phar/zip.c
    when handling the uncompressed file size. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (CVE-2016-7414)

  - Multiple stack-based buffer overflow conditions exist in
    the International Components for Unicode for C/C++
    (ICU4C) component in the msgfmt_format_message()
    function within file common/locid.cpp when handling
    locale strings. An unauthenticated, remote attacker can
    exploit these, via a long locale string, to cause a
    denial of service condition or the execution of
    arbitrary code. (CVE-2016-7415, CVE-2016-7416)

  - A flaw exists in PHP within file ext/spl/spl_array.c,
    specifically in the spl_array_get_dimension_ptr_ptr()
    function during the deserialization of SplArray, due to
    improper validation of types. An unauthenticated, remote
    attacker can exploit this to cause a crash or other
    unspecified impact. (CVE-2016-7417)

  - An out-of-bounds read error exists in PHP in the
    php_wddx_push_element() function within file
    ext/wddx/wddx.c. An unauthenticated, remote attacker
    can exploit this to cause a crash or the disclosure
    of memory contents. (CVE-2016-7418)

  - A use-after-free error exists in PHP within the
    unserialize() function in file ext/curl/curl_file.c. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-9137)

  - An integer overflow condition exists in PHP in the
    php_snmp_parse_oid() function in file ext/snmp/snmp.c.
    An unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in the
    execution of arbitrary code. (VulnDB 143100)

  - An integer overflow condition exists in PHP in the
    sql_regcase() function within file ext/ereg/ereg.c when
    handling overly long strings. An unauthenticated, remote
    attacker can exploit this to corrupt memory, resulting
    in the execution of arbitrary code. (VulnDB 143102)

  - An integer overflow condition exists in PHP in the
    php_base64_encode() function within file
    ext/standard/base64.c when handling overly long
    strings. An unauthenticated, remote attacker can exploit
    this to corrupt memory, resulting in the execution of
    arbitrary code. (VulnDB 143105)

  - An integer overflow condition exists in PHP in the
    php_quot_print_encode() function within file
    ext/standard/quot_print.c when handling overly long
    strings. An unauthenticated, remote attacker can
    exploit this to cause a heap-based buffer overflow,
    resulting in the execution of arbitrary code.
    (VulnDB 143107)

  - A use-after-free error exists in PHP in the
    unserialize() function within file ext/standard/var.c.
    An unauthenticated, remote attacker can exploit this to
    dereference already freed memory, resulting in the
    execution of arbitrary code. (VulnDB 143108)

  - A flaw exists in PHP in the php_ftp_fopen_connect()
    function within file ext/standard/ftp_fopen_wrapper.c
    due to silently downgrading to regular FTP even if a
    secure method has been requested. A man-in-the-middle
    (MitM) attacker can exploit this to downgrade the FTP
    communication. (VulnDB 143109)

  - An integer overflow condition exists in PHP in the
    php_url_encode() function within file ext/standard/url.c
    when handling overly long strings. An unauthenticated,
    remote attacker can exploit this to corrupt memory,
    resulting in the execution of arbitrary code.
    (VulnDB 143112)

  - An integer overflow condition exists in PHP in the
    php_uuencode() function in file ext/standard/uuencode.c.
    An unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (VulnDB 143113)

  - An integer overflow condition exists in PHP in the
    bzdecompress() function within file ext/bz2/bz2.c. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (VulnDB 143114)

  - An integer overflow condition exists in PHP in the
    curl_escape() function within file ext/curl/interface.c
    when handling overly long escaped strings. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in the execution of arbitrary
    code. (VulnDB 143117)

  - An out-of-bounds access error exists in PHP in file
    ext/phar/tar.c, specifically in the phar_parse_tarfile()
    function during the verification of signatures. An
    unauthenticated, remote attacker can exploit this to
    have an unspecified impact. (VulnDB 144264)

  - A flaw exists in PHP when destroying deserialized
    objects due to improper validation of certain
    unspecified input. An unauthenticated, remote attacker
    can exploit this to corrupt memory, resulting in a
    denial of service condition or the execution of
    arbitrary code. (VulnDB 144268)

  - An integer overflow condition exists in PHP within the
    fgetcsv() function due to improper validation of CSV
    field lengths. An unauthenticated, remote attacker can
    exploit this to corrupt memory, resulting in a denial of
    service condition or the execution of arbitrary code.
    (VulnDB 144270)

  - An integer overflow condition exists in PHP in the
    wordwrap() function within file ext/standard/string.c
    due to improper validation of certain unspecified input.
    An unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 144271)

  - An integer overflow condition exists in PHP in the
    fgets() function within file ext/standard/file.c due to
    improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 144273)

  - An integer overflow condition exists in PHP in the
    xml_utf8_encode() function within file ext/xml/xml.c due
    to improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit this to
    cause an unspecified impact. (VulnDB 144275)

  - A flaw exists in PHP in the exif_process_IFD_in_TIFF()
    function within file ext/exif/exif.c when handling
    uninitialized thumbnail data. An unauthenticated, remote
    attacker can exploit this to disclose memory contents.
    (VulnDB 144287)

  - A flaw exists in PHP due to the parse_url() function
    returning the incorrect host. An unauthenticated, remote
    attacker can exploit this to bypass authentication or to
    conduct open redirection and server-side request forgery
    attacks, depending on how the function is implemented.
    (VulnDB 145227)

  - A NULL pointer dereference flaw exists in PHP in the
    SimpleXMLElement::asXML() function within file
    ext/simplexml/simplexml.c. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 145598)

  - An heap buffer overflow condition exists in PHP in the
    php_ereg_replace() function within file ext/ereg/ereg.c
    due to improper validation of certain unspecified input.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition or the execution of
    arbitrary code. (VulnDB 145599)

  - A flaw exists in PHP in file ext/openssl/openssl.c
    within the openssl_random_pseudo_bytes() function when
    handling strings larger than 2GB. An unauthenticated,
    remote attacker can exploit this to cause a denial of
    service condition. (VulnDB 145600)

  - A flaw exists in PHP in the openssl_encrypt() function
    within file ext/openssl/openssl.c when handling strings
    larger than 2GB. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (VulnDB 145601)

  - An integer overflow condition exists in PHP in the
    imap_8bit() function within file ext/imap/php_imap.c due
    to improper validation of certain unspecified input. An
    unauthenticated, remote attacker can exploit this to
    corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 145602)

  - A flaw exists in PHP in the _bc_new_num_ex() function
    within file ext/bcmath/libbcmath/src/init.c when
    handling values passed via the 'scale' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 145603)

  - A flaw exists in PHP in the php_resolve_path() function
    within file main/fopen_wrappers.c when handling negative
    size values passed via the 'filename' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 145604)

  - A flaw exists in PHP in the dom_document_save_html()
    function within file ext/dom/document.c due to missing
    NULL checks. An unauthenticated, remote attacker can
    exploit this to cause a denial of service condition.
    (VulnDB 145605)

  - An integer overflow condition exists in PHP in the
    mb_encode_*() function in file ext/mbstring/mbstring.c
    due to improper validation of the length of encoded
    data. An unauthenticated, remote attacker can exploit
    this to corrupt memory, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 145607)

  - A NULL pointer dereference flaw exists in PHP in the
    CachingIterator() function within file
    ext/spl/spl_iterators.c when handling string conversion.
    An unauthenticated, remote attacker can exploit this to
    cause a denial of service condition. (VulnDB 145608)

  - An integer overflow condition exists in PHP in the
    number_format() function within file ext/standard/math.c
    when handling 'decimals' and 'dec_point' parameters with
    values equal or close to 0x7FFFFFFF. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 145609)

  - A overflow condition exists in PHP within file
    ext/intl/resourcebundle/resourcebundle_class.c,
    specifically in functions ResourceBundle::create() and
    ResourceBundle::getLocales(), due to improper validation
    of input passed via the 'bundlename' parameter. An
    unauthenticated, remote attacker can exploit this to
    cause a stack-based buffer overflow, resulting in a
    denial of service condition or the execution of
    arbitrary code. (VulnDB 145610)

  - An integer overflow condition exists in PHP in the
    php_pcre_replace_impl() function within file
    ext/pcre/php_pcre.c due to improper validation of
    certain unspecified input. An unauthenticated, remote
    attacker can exploit this to cause a heap-based buffer
    overflow, resulting in a denial of service condition or
    the execution of arbitrary code. (VulnDB 145611)

  - An integer overflow condition exists in PHP in the
    _php_imap_mail() function in file ext/imap/php_imap.c
    when handling overly long strings. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or the execution of arbitrary code.
    (VulnDB 146957)

  - A flaw exists in PHP in the bzcompress() function when
    handling overly long strings. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (VulnDB 146975)

  - An integer overflow condition exists in PHP in the
    gdImageAALine() function within file ext/gd/libgd/gd.c
    due to improper validation of line limit values.
    An unauthenticated, remote attacker can exploit this to
    cause an out-of-bounds write or read, resulting in a
    denial of service condition, the disclosure of memory
    contents, or the execution of arbitrary code.
    (VulnDB 147321)

  - Multiple stored cross-site scripting (XSS)
    vulnerabilities exist in unspecified scripts due to
    improper validation of input before returning it to
    users. An unauthenticated, remote attacker can exploit
    these, via a specially crafted request, to execute
    arbitrary script code in a user's browser session.
    (VulnDB 147910, 147911, 147912, 147913, 147914, 147915,
    147916, 147917, 147918)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://www.tenable.com/security/tns-2016-19");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.4.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

version = get_kb_item("Host/SecurityCenter/Version");
if(empty_or_null(version))
{
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  version = install["version"];
}
fix = "5.4.1";

if ( version =~ "^5\.[0-3]([^0-9]|$)" || version =~ "^5\.4\.0([^0-9]|$)" )
{
  items = make_array("Installed version", version,
                     "Fixed version", fix
                    );

  order = make_list("Installed version", "Fixed version");
  report = report_items_str(report_items:items, ordered_fields:order);

  security_report_v4(severity:SECURITY_HOLE, port:0, extra:report, xss:TRUE);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, 'SecurityCenter', version);
