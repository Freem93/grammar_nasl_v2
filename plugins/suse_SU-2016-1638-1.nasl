#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2016:1638-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(93161);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/12/27 20:24:09 $");

  script_cve_id("CVE-2004-1019", "CVE-2006-7243", "CVE-2014-0207", "CVE-2014-3478", "CVE-2014-3479", "CVE-2014-3480", "CVE-2014-3487", "CVE-2014-3515", "CVE-2014-3597", "CVE-2014-3668", "CVE-2014-3669", "CVE-2014-3670", "CVE-2014-4049", "CVE-2014-4670", "CVE-2014-4698", "CVE-2014-4721", "CVE-2014-5459", "CVE-2014-8142", "CVE-2014-9652", "CVE-2014-9705", "CVE-2014-9709", "CVE-2014-9767", "CVE-2015-0231", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-1352", "CVE-2015-2301", "CVE-2015-2305", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3152", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4116", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4643", "CVE-2015-4644", "CVE-2015-5161", "CVE-2015-5589", "CVE-2015-5590", "CVE-2015-6831", "CVE-2015-6833", "CVE-2015-6836", "CVE-2015-6837", "CVE-2015-6838", "CVE-2015-7803", "CVE-2015-8835", "CVE-2015-8838", "CVE-2015-8866", "CVE-2015-8867", "CVE-2015-8873", "CVE-2015-8874", "CVE-2015-8879", "CVE-2016-2554", "CVE-2016-3141", "CVE-2016-3142", "CVE-2016-3185", "CVE-2016-4070", "CVE-2016-4073", "CVE-2016-4342", "CVE-2016-4346", "CVE-2016-4537", "CVE-2016-4538", "CVE-2016-4539", "CVE-2016-4540", "CVE-2016-4541", "CVE-2016-4542", "CVE-2016-4543", "CVE-2016-4544", "CVE-2016-5093", "CVE-2016-5094", "CVE-2016-5095", "CVE-2016-5096", "CVE-2016-5114");
  script_bugtraq_id(44951, 68007, 68120, 68237, 68238, 68239, 68241, 68243, 68423, 68511, 68513, 69322, 69388, 70611, 70665, 70666, 71791, 71932, 72505, 72539, 72541, 72611, 72701, 73031, 73037, 73306, 73431, 74239, 74240, 74398, 74413, 74700, 74902, 74903, 75056, 75103, 75244, 75246, 75249, 75250, 75251, 75252, 75255, 75291, 75292, 75970, 75974);
  script_osvdb_id(12415, 70606, 107994, 108462, 108463, 108464, 108465, 108466, 108467, 108468, 108946, 108947, 110250, 110251, 110441, 113421, 113422, 113423, 115011, 116020, 117467, 117469, 117588, 118433, 118582, 118589, 119650, 119772, 119774, 120925, 120926, 120938, 121398, 121459, 121460, 121461, 122125, 122126, 122127, 122261, 122735, 123148, 123639, 123640, 123677, 124239, 124242, 125783, 125849, 125850, 125851, 125852, 125854, 125855, 125857, 125858, 125859, 126952, 126989, 127122, 128347, 132662, 134031, 134034, 135224, 135225, 135227, 136485, 136486, 137454, 137753, 137758, 137781, 137782, 137783, 137784, 138996, 138997, 139005);

  script_name(english:"SUSE SLES11 Security Update : php53 (SUSE-SU-2016:1638-1) (BACKRONYM)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for php53 to version 5.3.17 fixes the following issues :

These security issues were fixed :

  - CVE-2016-5093: get_icu_value_internal out-of-bounds read
    (bnc#982010).

  - CVE-2016-5094: Don't create strings with lengths outside
    int range (bnc#982011).

  - CVE-2016-5095: Don't create strings with lengths outside
    int range (bnc#982012).

  - CVE-2016-5096: int/size_t confusion in fread
    (bsc#982013).

  - CVE-2016-5114: fpm_log.c memory leak and buffer overflow
    (bnc#982162).

  - CVE-2015-8879: The odbc_bindcols function in
    ext/odbc/php_odbc.c in PHP mishandles driver behavior
    for SQL_WVARCHAR columns, which allowed remote attackers
    to cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table (bsc#981050).

  - CVE-2015-4116: Use-after-free vulnerability in the
    spl_ptr_heap_insert function in ext/spl/spl_heap.c in
    PHP allowed remote attackers to execute arbitrary code
    by triggering a failed SplMinHeap::compare operation
    (bsc#980366).

  - CVE-2015-8874: Stack consumption vulnerability in GD in
    PHP allowed remote attackers to cause a denial of
    service via a crafted imagefilltoborder call
    (bsc#980375).

  - CVE-2015-8873: Stack consumption vulnerability in
    Zend/zend_exceptions.c in PHP allowed remote attackers
    to cause a denial of service (segmentation fault) via
    recursive method calls (bsc#980373).

  - CVE-2016-4540: The grapheme_stripos function in
    ext/intl/grapheme/grapheme_string.c in PHP allowed
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset (bsc#978829).

  - CVE-2016-4541: The grapheme_strpos function in
    ext/intl/grapheme/grapheme_string.c in PHP allowed
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset (bsc#978829.

  - CVE-2016-4542: The exif_process_IFD_TAG function in
    ext/exif/exif.c in PHP did not properly construct
    spprintf arguments, which allowed remote attackers to
    cause a denial of service (out-of-bounds read) or
    possibly have unspecified other impact via crafted
    header data (bsc#978830).

  - CVE-2016-4543: The exif_process_IFD_in_JPEG function in
    ext/exif/exif.c in PHP did not validate IFD sizes, which
    allowed remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via crafted header data (bsc#978830.

  - CVE-2016-4544: The exif_process_TIFF_in_JPEG function in
    ext/exif/exif.c in PHP did not validate TIFF start data,
    which allowed remote attackers to cause a denial of
    service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header data
    (bsc#978830.

  - CVE-2016-4537: The bcpowmod function in
    ext/bcmath/bcmath.c in PHP accepted a negative integer
    for the scale argument, which allowed remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via a crafted call
    (bsc#978827).

  - CVE-2016-4538: The bcpowmod function in
    ext/bcmath/bcmath.c in PHP modified certain data
    structures without considering whether they are copies
    of the _zero_, _one_, or _two_ global variable, which
    allowed remote attackers to cause a denial of service or
    possibly have unspecified other impact via a crafted
    call (bsc#978827).

  - CVE-2016-4539: The xml_parse_into_struct function in
    ext/xml/xml.c in PHP allowed remote attackers to cause a
    denial of service (buffer under-read and segmentation
    fault) or possibly have unspecified other impact via
    crafted XML data in the second argument, leading to a
    parser level of zero (bsc#978828).

  - CVE-2016-4342: ext/phar/phar_object.c in PHP mishandles
    zero-length uncompressed data, which allowed remote
    attackers to cause a denial of service (heap memory
    corruption) or possibly have unspecified other impact
    via a crafted (1) TAR, (2) ZIP, or (3) PHAR archive
    (bsc#977991).

  - CVE-2016-4346: Integer overflow in the str_pad function
    in ext/standard/string.c in PHP allowed remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via a long string, leading to a
    heap-based buffer overflow (bsc#977994).

  - CVE-2016-4073: Multiple integer overflows in the
    mbfl_strcut function in
    ext/mbstring/libmbfl/mbfl/mbfilter.c in PHP allowed
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted mb_strcut call (bsc#977003).

  - CVE-2015-8867: The openssl_random_pseudo_bytes function
    in ext/openssl/openssl.c in PHP incorrectly relied on
    the deprecated RAND_pseudo_bytes function, which made it
    easier for remote attackers to defeat cryptographic
    protection mechanisms via unspecified vectors
    (bsc#977005).

  - CVE-2016-4070: Integer overflow in the
    php_raw_url_encode function in ext/standard/url.c in PHP
    allowed remote attackers to cause a denial of service
    (application crash) via a long string to the
    rawurlencode function (bsc#976997).

  - CVE-2015-8866: ext/libxml/libxml.c in PHP when PHP-FPM
    is used, did not isolate each thread from
    libxml_disable_entity_loader changes in other threads,
    which allowed remote attackers to conduct XML External
    Entity (XXE) and XML Entity Expansion (XEE) attacks via
    a crafted XML document, a related issue to CVE-2015-5161
    (bsc#976996).

  - CVE-2015-8838: ext/mysqlnd/mysqlnd.c in PHP used a
    client SSL option to mean that SSL is optional, which
    allowed man-in-the-middle attackers to spoof servers via
    a cleartext-downgrade attack, a related issue to
    CVE-2015-3152 (bsc#973792).

  - CVE-2015-8835: The make_http_soap_request function in
    ext/soap/php_http.c in PHP did not properly retrieve
    keys, which allowed remote attackers to cause a denial
    of service (NULL pointer dereference, type confusion,
    and application crash) or possibly execute arbitrary
    code via crafted serialized data representing a
    numerically indexed _cookies array, related to the
    SoapClient::__call method in ext/soap/soap.c
    (bsc#973351).

  - CVE-2016-3141: Use-after-free vulnerability in wddx.c in
    the WDDX extension in PHP allowed remote attackers to
    cause a denial of service (memory corruption and
    application crash) or possibly have unspecified other
    impact by triggering a wddx_deserialize call on XML data
    containing a crafted var element (bsc#969821).

  - CVE-2016-3142: The phar_parse_zipfile function in zip.c
    in the PHAR extension in PHP allowed remote attackers to
    obtain sensitive information from process memory or
    cause a denial of service (out-of-bounds read and
    application crash) by placing a PK\x05\x06 signature at
    an invalid location (bsc#971912).

  - CVE-2014-9767: Directory traversal vulnerability in the
    ZipArchive::extractTo function in ext/zip/php_zip.c in
    PHP ext/zip/ext_zip.cpp in HHVM allowed remote attackers
    to create arbitrary empty directories via a crafted ZIP
    archive (bsc#971612).

  - CVE-2016-3185: The make_http_soap_request function in
    ext/soap/php_http.c in PHP allowed remote attackers to
    obtain sensitive information from process memory or
    cause a denial of service (type confusion and
    application crash) via crafted serialized _cookies data,
    related to the SoapClient::__call method in
    ext/soap/soap.c (bsc#971611).

  - CVE-2016-2554: Stack-based buffer overflow in
    ext/phar/tar.c in PHP allowed remote attackers to cause
    a denial of service (application crash) or possibly have
    unspecified other impact via a crafted TAR archive
    (bsc#968284).

  - CVE-2015-7803: The phar_get_entry_data function in
    ext/phar/util.c in PHP allowed remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a .phar file with a crafted TAR
    archive entry in which the Link indicator references a
    file that did not exist (bsc#949961).

  - CVE-2015-6831: Multiple use-after-free vulnerabilities
    in SPL in PHP allowed remote attackers to execute
    arbitrary code via vectors involving (1) ArrayObject,
    (2) SplObjectStorage, and (3) SplDoublyLinkedList, which
    are mishandled during unserialization (bsc#942291).

  - CVE-2015-6833: Directory traversal vulnerability in the
    PharData class in PHP allowed remote attackers to write
    to arbitrary files via a .. (dot dot) in a ZIP archive
    entry that is mishandled during an extractTo call
    (bsc#942296.

  - CVE-2015-6836: The SoapClient __call method in
    ext/soap/soap.c in PHP did not properly manage headers,
    which allowed remote attackers to execute arbitrary code
    via crafted serialized data that triggers a 'type
    confusion' in the serialize_function_call function
    (bsc#945428).

  - CVE-2015-6837: The xsl_ext_function_php function in
    ext/xsl/xsltprocessor.c in PHP when libxml2 is used, did
    not consider the possibility of a NULL valuePop return
    value proceeding with a free operation during initial
    error checking, which allowed remote attackers to cause
    a denial of service (NULL pointer dereference and
    application crash) via a crafted XML document, a
    different vulnerability than CVE-2015-6838 (bsc#945412).

  - CVE-2015-6838: The xsl_ext_function_php function in
    ext/xsl/xsltprocessor.c in PHP when libxml2 is used, did
    not consider the possibility of a NULL valuePop return
    value proceeding with a free operation after the
    principal argument loop, which allowed remote attackers
    to cause a denial of service (NULL pointer dereference
    and application crash) via a crafted XML document, a
    different vulnerability than CVE-2015-6837 (bsc#945412).

  - CVE-2015-5590: Stack-based buffer overflow in the
    phar_fix_filepath function in ext/phar/phar.c in PHP
    allowed remote attackers to cause a denial of service or
    possibly have unspecified other impact via a large
    length value, as demonstrated by mishandling of an
    e-mail attachment by the imap PHP extension
    (bsc#938719).

  - CVE-2015-5589: The phar_convert_to_other function in
    ext/phar/phar_object.c in PHP did not validate a file
    pointer a close operation, which allowed remote
    attackers to cause a denial of service (segmentation
    fault) or possibly have unspecified other impact via a
    crafted TAR archive that is mishandled in a
    Phar::convertToData call (bsc#938721).

  - CVE-2015-4602: The __PHP_Incomplete_Class function in
    ext/standard/incomplete_class.c in PHP allowed remote
    attackers to cause a denial of service (application
    crash) or possibly execute arbitrary code via an
    unexpected data type, related to a 'type confusion'
    issue (bsc#935224).

  - CVE-2015-4599: The SoapFault::__toString method in
    ext/soap/soap.c in PHP allowed remote attackers to
    obtain sensitive information, cause a denial of service
    (application crash), or possibly execute arbitrary code
    via an unexpected data type, related to a 'type
    confusion' issue (bsc#935226).

  - CVE-2015-4600: The SoapClient implementation in PHP
    allowed remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via an unexpected data type, related to 'type confusion'
    issues in the (1) SoapClient::__getLastRequest, (2)
    SoapClient::__getLastResponse, (3)
    SoapClient::__getLastRequestHeaders, (4)
    SoapClient::__getLastResponseHeaders, (5)
    SoapClient::__getCookies, and (6)
    SoapClient::__setCookie methods (bsc#935226).

  - CVE-2015-4601: PHP allowed remote attackers to cause a
    denial of service (application crash) or possibly
    execute arbitrary code via an unexpected data type,
    related to 'type confusion' issues in (1)
    ext/soap/php_encoding.c, (2) ext/soap/php_http.c, and
    (3) ext/soap/soap.c, a different issue than
    CVE-2015-4600 (bsc#935226.

  - CVE-2015-4603: The exception::getTraceAsString function
    in Zend/zend_exceptions.c in PHP allowed remote
    attackers to execute arbitrary code via an unexpected
    data type, related to a 'type confusion' issue
    (bsc#935234).

  - CVE-2015-4644: The php_pgsql_meta_data function in
    pgsql.c in the PostgreSQL (aka pgsql) extension in PHP
    did not validate token extraction for table names, which
    might allowed remote attackers to cause a denial of
    service (NULL pointer dereference and application crash)
    via a crafted name. NOTE: this vulnerability exists
    because of an incomplete fix for CVE-2015-1352
    (bsc#935274).

  - CVE-2015-4643: Integer overflow in the ftp_genlist
    function in ext/ftp/ftp.c in PHP allowed remote FTP
    servers to execute arbitrary code via a long reply to a
    LIST command, leading to a heap-based buffer overflow.
    NOTE: this vulnerability exists because of an incomplete
    fix for CVE-2015-4022 (bsc#935275).

  - CVE-2015-3411: PHP did not ensure that pathnames lack
    %00 sequences, which might have allowed remote attackers
    to read or write to arbitrary files via crafted input to
    an application that calls (1) a DOMDocument load method,
    (2) the xmlwriter_open_uri function, (3) the finfo_file
    function, or (4) the hash_hmac_file function, as
    demonstrated by a filename\0.xml attack that bypasses an
    intended configuration in which client users may read
    only .xml files (bsc#935227).

  - CVE-2015-3412: PHP did not ensure that pathnames lack
    %00 sequences, which might have allowed remote attackers
    to read arbitrary files via crafted input to an
    application that calls the stream_resolve_include_path
    function in ext/standard/streamsfuncs.c, as demonstrated
    by a filename\0.extension attack that bypasses an
    intended configuration in which client users may read
    files with only one specific extension (bsc#935229).

  - CVE-2015-4598: PHP did not ensure that pathnames lack
    %00 sequences, which might have allowed remote attackers
    to read or write to arbitrary files via crafted input to
    an application that calls (1) a DOMDocument save method
    or (2) the GD imagepsloadfont function, as demonstrated
    by a filename\0.html attack that bypasses an intended
    configuration in which client users may write to only
    .html files (bsc#935232).

  - CVE-2015-4148: The do_soap_call function in
    ext/soap/soap.c in PHP did not verify that the uri
    property is a string, which allowed remote attackers to
    obtain sensitive information by providing crafted
    serialized data with an int data type, related to a
    'type confusion' issue (bsc#933227).

  - CVE-2015-4024: Algorithmic complexity vulnerability in
    the multipart_buffer_headers function in main/rfc1867.c
    in PHP allowed remote attackers to cause a denial of
    service (CPU consumption) via crafted form data that
    triggers an improper order-of-growth outcome
    (bsc#931421).

  - CVE-2015-4026: The pcntl_exec implementation in PHP
    truncates a pathname upon encountering a \x00 character,
    which might allowed remote attackers to bypass intended
    extension restrictions and execute files with unexpected
    names via a crafted first argument. NOTE: this
    vulnerability exists because of an incomplete fix for
    CVE-2006-7243 (bsc#931776).

  - CVE-2015-4022: Integer overflow in the ftp_genlist
    function in ext/ftp/ftp.c in PHP allowed remote FTP
    servers to execute arbitrary code via a long reply to a
    LIST command, leading to a heap-based buffer overflow
    (bsc#931772).

  - CVE-2015-4021: The phar_parse_tarfile function in
    ext/phar/tar.c in PHP did not verify that the first
    character of a filename is different from the \0
    character, which allowed remote attackers to cause a
    denial of service (integer underflow and memory
    corruption) via a crafted entry in a tar archive
    (bsc#931769).

  - CVE-2015-3329: Multiple stack-based buffer overflows in
    the phar_set_inode function in phar_internal.h in PHP
    allowed remote attackers to execute arbitrary code via a
    crafted length value in a (1) tar, (2) phar, or (3) ZIP
    archive (bsc#928506).

  - CVE-2015-2783: ext/phar/phar.c in PHP allowed remote
    attackers to obtain sensitive information from process
    memory or cause a denial of service (buffer over-read
    and application crash) via a crafted length value in
    conjunction with crafted serialized data in a phar
    archive, related to the phar_parse_metadata and
    phar_parse_pharfile functions (bsc#928511).

  - CVE-2015-2787: Use-after-free vulnerability in the
    process_nested_data function in
    ext/standard/var_unserializer.re in PHP allowed remote
    attackers to execute arbitrary code via a crafted
    unserialize call that leverages use of the unset
    function within an __wakeup function, a related issue to
    CVE-2015-0231 (bsc#924972).

  - CVE-2014-9709: The GetCode_ function in gd_gif_in.c in
    GD 2.1.1 and earlier, as used in PHP allowed remote
    attackers to cause a denial of service (buffer over-read
    and application crash) via a crafted GIF image that is
    improperly handled by the gdImageCreateFromGif function
    (bsc#923945).

  - CVE-2015-2301: Use-after-free vulnerability in the
    phar_rename_archive function in phar_object.c in PHP
    allowed remote attackers to cause a denial of service or
    possibly have unspecified other impact via vectors that
    trigger an attempted renaming of a Phar archive to the
    name of an existing file (bsc#922452).

  - CVE-2015-2305: Integer overflow in the regcomp
    implementation in the Henry Spencer BSD regex library
    (aka rxspencer) 32-bit platforms might have allowed
    context-dependent attackers to execute arbitrary code
    via a large regular expression that leads to a
    heap-based buffer overflow (bsc#921950).

  - CVE-2014-9705: Heap-based buffer overflow in the
    enchant_broker_request_dict function in
    ext/enchant/enchant.c in PHP allowed remote attackers to
    execute arbitrary code via vectors that trigger creation
    of multiple dictionaries (bsc#922451).

  - CVE-2015-0273: Multiple use-after-free vulnerabilities
    in ext/date/php_date.c in PHP allowed remote attackers
    to execute arbitrary code via crafted serialized input
    containing a (1) R or (2) r type specifier in (a)
    DateTimeZone data handled by the
    php_date_timezone_initialize_from_hash function or (b)
    DateTime data handled by the
    php_date_initialize_from_hash function (bsc#918768).

  - CVE-2014-9652: The mconvert function in softmagic.c in
    file as used in the Fileinfo component in PHP did not
    properly handle a certain string-length field during a
    copy of a truncated version of a Pascal string, which
    might allowed remote attackers to cause a denial of
    service (out-of-bounds memory access and application
    crash) via a crafted file (bsc#917150).

  - CVE-2014-8142: Use-after-free vulnerability in the
    process_nested_data function in
    ext/standard/var_unserializer.re in PHP allowed remote
    attackers to execute arbitrary code via a crafted
    unserialize call that leverages improper handling of
    duplicate keys within the serialized properties of an
    object, a different vulnerability than CVE-2004-1019
    (bsc#910659).

  - CVE-2015-0231: Use-after-free vulnerability in the
    process_nested_data function in
    ext/standard/var_unserializer.re in PHP allowed remote
    attackers to execute arbitrary code via a crafted
    unserialize call that leverages improper handling of
    duplicate numerical keys within the serialized
    properties of an object. NOTE: this vulnerability exists
    because of an incomplete fix for CVE-2014-8142
    (bsc#910659).

  - CVE-2014-8142: Use-after-free vulnerability in the
    process_nested_data function in
    ext/standard/var_unserializer.re in PHP allowed remote
    attackers to execute arbitrary code via a crafted
    unserialize call that leverages improper handling of
    duplicate keys within the serialized properties of an
    object, a different vulnerability than CVE-2004-1019
    (bsc#910659).

  - CVE-2015-0232: The exif_process_unicode function in
    ext/exif/exif.c in PHP allowed remote attackers to
    execute arbitrary code or cause a denial of service
    (uninitialized pointer free and application crash) via
    crafted EXIF data in a JPEG image (bsc#914690).

  - CVE-2014-3670: The exif_ifd_make_value function in
    exif.c in the EXIF extension in PHP operates on
    floating-point arrays incorrectly, which allowed remote
    attackers to cause a denial of service (heap memory
    corruption and application crash) or possibly execute
    arbitrary code via a crafted JPEG image with TIFF
    thumbnail data that is improperly handled by the
    exif_thumbnail function (bsc#902357).

  - CVE-2014-3669: Integer overflow in the object_custom
    function in ext/standard/var_unserializer.c in PHP
    allowed remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via an argument to the unserialize function that
    triggers calculation of a large length value
    (bsc#902360).

  - CVE-2014-3668: Buffer overflow in the date_from_ISO8601
    function in the mkgmtime implementation in
    libxmlrpc/xmlrpc.c in the XMLRPC extension in PHP
    allowed remote attackers to cause a denial of service
    (application crash) via (1) a crafted first argument to
    the xmlrpc_set_type function or (2) a crafted argument
    to the xmlrpc_decode function, related to an
    out-of-bounds read operation (bsc#902368).

  - CVE-2014-5459: The PEAR_REST class in REST.php in PEAR
    in PHP allowed local users to write to arbitrary files
    via a symlink attack on a (1) rest.cachefile or (2)
    rest.cacheid file in /tmp/pear/cache/, related to the
    retrieveCacheFirst and useLocalCache functions
    (bsc#893849).

  - CVE-2014-3597: Multiple buffer overflows in the
    php_parserr function in ext/standard/dns.c in PHP
    allowed remote DNS servers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted DNS record, related to the dns_get_record
    function and the dn_expand function. NOTE: this issue
    exists because of an incomplete fix for CVE-2014-4049
    (bsc#893853).

  - CVE-2014-4670: Use-after-free vulnerability in
    ext/spl/spl_dllist.c in the SPL component in PHP allowed
    context-dependent attackers to cause a denial of service
    or possibly have unspecified other impact via crafted
    iterator usage within applications in certain
    web-hosting environments (bsc#886059).

  - CVE-2014-4698: Use-after-free vulnerability in
    ext/spl/spl_array.c in the SPL component in PHP allowed
    context-dependent attackers to cause a denial of service
    or possibly have unspecified other impact via crafted
    ArrayIterator usage within applications in certain
    web-hosting environments (bsc#886060).

  - CVE-2014-4721: The phpinfo implementation in
    ext/standard/info.c in PHP did not ensure use of the
    string data type for the PHP_AUTH_PW, PHP_AUTH_TYPE,
    PHP_AUTH_USER, and PHP_SELF variables, which might
    allowed context-dependent attackers to obtain sensitive
    information from process memory by using the integer
    data type with crafted values, related to a 'type
    confusion' vulnerability, as demonstrated by reading a
    private SSL key in an Apache HTTP Server web-hosting
    environment with mod_ssl and a PHP 5.3.x mod_php
    (bsc#885961).

  - CVE-2014-0207: The cdf_read_short_sector function in
    cdf.c in file as used in the Fileinfo component in PHP
    allowed remote attackers to cause a denial of service
    (assertion failure and application exit) via a crafted
    CDF file (bsc#884986).

  - CVE-2014-3478: Buffer overflow in the mconvert function
    in softmagic.c in file as used in the Fileinfo component
    in PHP allowed remote attackers to cause a denial of
    service (application crash) via a crafted Pascal string
    in a FILE_PSTRING conversion (bsc#884987).

  - CVE-2014-3479: The cdf_check_stream_offset function in
    cdf.c in file as used in the Fileinfo component in PHP
    relies on incorrect sector-size data, which allowed
    remote attackers to cause a denial of service
    (application crash) via a crafted stream offset in a CDF
    file (bsc#884989).

  - CVE-2014-3480: The cdf_count_chain function in cdf.c in
    file as used in the Fileinfo component in PHP did not
    properly validate sector-count data, which allowed
    remote attackers to cause a denial of service
    (application crash) via a crafted CDF file (bsc#884990).

  - CVE-2014-3487: The cdf_read_property_info function in
    file as used in the Fileinfo component in PHP did not
    properly validate a stream offset, which allowed remote
    attackers to cause a denial of service (application
    crash) via a crafted CDF file (bsc#884991).

  - CVE-2014-3515: The SPL component in PHP incorrectly
    anticipates that certain data structures will have the
    array data type after unserialization, which allowed
    remote attackers to execute arbitrary code via a crafted
    string that triggers use of a Hashtable destructor,
    related to 'type confusion' issues in (1) ArrayObject
    and (2) SPLObjectStorage (bsc#884992).

These non-security issues were fixed :

  - bnc#935074: compare with SQL_NULL_DATA correctly

  - bnc#935074: fix segfault in odbc_fetch_array

  - bnc#919080: fix timezone map

  - bnc#925109: unserialize SoapClient type confusion

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884986"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884987"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884989"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/884992"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/885961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886059"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/886060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/893849"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/893853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902357"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902360"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/902368"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/910659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/914690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/917150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/918768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/919080"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/921950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/922452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/923945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/924972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/925109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/928511"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931421"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931772"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/931776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/933227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935074"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935224"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935226"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935227"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935274"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/935275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938719"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/938721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/942296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/945428"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/949961"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/968284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/969821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971611"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/971912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973351"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/973792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/976997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977005"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977991"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/977994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978827"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978828"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/978830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/980375"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/981050"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/982162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2004-1019.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2006-7243.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-0207.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3480.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3515.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3668.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3669.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-3670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4670.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4698.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-4721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-5459.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-8142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9767.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0231.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-0273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-1352.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2305.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-2787.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3152.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-3412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4116.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4599.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4602.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4603.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-4644.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5161.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5589.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-5590.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6831.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6833.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6836.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6837.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-6838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-7803.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8835.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8838.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8866.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8867.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8873.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8874.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2015-8879.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-2554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3141.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3142.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-3185.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4070.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4073.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4346.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4537.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4538.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4539.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4540.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4541.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4542.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4543.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-4544.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2016-5114.html"
  );
  # https://www.suse.com/support/update/announcement/2016/suse-su-20161638-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?10285483"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP2-LTSS :

zypper in -t patch slessp2-php53-12621=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:X/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:apache2-mod_php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-bz2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-calendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ctype");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-dom");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-exif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fastcgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-fileinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-gmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-iconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pcntl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-shmop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-suhosin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvmsg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvsem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-sysvshm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-wddx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlreader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xmlwriter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-xsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:php53-zlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"2", reference:"apache2-mod_php53-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-bcmath-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-bz2-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-calendar-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-ctype-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-curl-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-dba-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-dom-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-exif-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-fastcgi-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-fileinfo-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-ftp-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-gd-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-gettext-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-gmp-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-iconv-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-intl-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-json-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-ldap-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-mbstring-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-mcrypt-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-mysql-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-odbc-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-openssl-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-pcntl-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-pdo-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-pear-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-pgsql-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-pspell-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-shmop-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-snmp-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-soap-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-suhosin-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-sysvmsg-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-sysvsem-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-sysvshm-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-tokenizer-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-wddx-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-xmlreader-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-xmlrpc-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-xmlwriter-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-xsl-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-zip-5.3.17-47.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"php53-zlib-5.3.17-47.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php53");
}
