#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99915);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2017/05/03 19:31:05 $");

  script_cve_id(
    "CVE-2016-4342",
    "CVE-2016-4343",
    "CVE-2016-6290",
    "CVE-2016-6295",
    "CVE-2016-6296",
    "CVE-2016-6297",
    "CVE-2016-7127",
    "CVE-2016-7129",
    "CVE-2016-7130",
    "CVE-2016-7131",
    "CVE-2016-7132",
    "CVE-2016-7416",
    "CVE-2016-7417",
    "CVE-2016-7478"
  );
  script_osvdb_id(
    134031,
    134037,
    141942,
    141944,
    141957,
    142018,
    143103,
    143104,
    143106,
    143110,
    143116,
    144259,
    144263,
    149441
  );

  script_name(english:"EulerOS 2.0 SP2 : php (EulerOS-SA-2017-1068)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - Zend/zend_exceptions.c in PHP, possibly 5.x before
    5.6.28 and 7.x before 7.0.13, allows remote attackers
    to cause a denial of service (infinite loop) via a
    crafted Exception object in serialized data, a related
    issue to CVE-2015-8876.(CVE-2016-7478)

  - ext/spl/spl_array.c in PHP before 5.6.26 and 7.x before
    7.0.11 proceeds with SplArray unserialization without
    validating a return value and data type, which allows
    remote attackers to cause a denial of service or
    possibly have unspecified other impact via crafted
    serialized data.(CVE-2016-7417)

  - ext/phar/phar_object.c in PHP before 5.5.32, 5.6.x
    before 5.6.18, and 7.x before 7.0.3 mishandles
    zero-length uncompressed data, which allows remote
    attackers to cause a denial of service (heap memory
    corruption) or possibly have unspecified other impact
    via a crafted (1) TAR, (2) ZIP, or (3) PHAR
    archive.(CVE-2016-4342)

  - The php_wddx_process_data function in ext/wddx/wddx.c
    in PHP before 5.6.25 and 7.x before 7.0.10 allows
    remote attackers to cause a denial of service
    (segmentation fault) or possibly have unspecified other
    impact via an invalid ISO 8601 time value, as
    demonstrated by a wddx_deserialize call that mishandles
    a dateTime element in a wddxPacket XML
    document.(CVE-2016-7129)

  - Integer signedness error in the simplestring_addn
    function in simplestring.c in xmlrpc-epi through
    0.54.2, as used in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9, allows remote attackers
    to cause a denial of service (heap-based buffer
    overflow) or possibly have unspecified other impact via
    a long first argument to the PHP xmlrpc_encode_request
    function.(CVE-2016-6296)

  - ext/snmp/snmp.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 improperly interacts with
    the unserialize implementation and garbage collection,
    which allows remote attackers to cause a denial of
    service (use-after-free and application crash) or
    possibly have unspecified other impact via crafted
    serialized data, a related issue to
    CVE-2016-5773.(CVE-2016-6295)

  - ext/session/session.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 does not properly
    maintain a certain hash data structure, which allows
    remote attackers to cause a denial of service
    (use-after-free) or possibly have unspecified other
    impact via vectors related to session
    deserialization.(CVE-2016-6290)

  - Integer overflow in the php_stream_zip_opener function
    in ext/zip/zip_stream.c in PHP before 5.5.38, 5.6.x
    before 5.6.24, and 7.x before 7.0.9 allows remote
    attackers to cause a denial of service (stack-based
    buffer overflow) or possibly have unspecified other
    impact via a crafted zip:// URL.(CVE-2016-6297)

  - The phar_make_dirstream function in
    ext/phar/dirstream.c in PHP before 5.6.18 and 7.x
    before 7.0.3 mishandles zero-size ././@LongLink files,
    which allows remote attackers to cause a denial of
    service (uninitialized pointer dereference) or possibly
    have unspecified other impact via a crafted TAR
    archive.(CVE-2016-4343)

  - ext/intl/msgformat/msgformat_format.c in PHP before
    5.6.26 and 7.x before 7.0.11 does not properly restrict
    the locale length provided to the Locale class in the
    ICU library, which allows remote attackers to cause a
    denial of service (application crash) or possibly have
    unspecified other impact via a
    MessageFormatter::formatMessage call with a long first
    argument.(CVE-2016-7416)

  - ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before
    7.0.10 allows remote attackers to cause a denial of
    service (NULL pointer dereference and application
    crash) or possibly have unspecified other impact via a
    malformed wddxPacket XML document that is mishandled in
    a wddx_deserialize call, as demonstrated by a tag that
    lacks a < (less than) character.(CVE-2016-7131)

  - ext/wddx/wddx.c in PHP before 5.6.25 and 7.x before
    7.0.10 allows remote attackers to cause a denial of
    service (NULL pointer dereference and application
    crash) or possibly have unspecified other impact via an
    invalid wddxPacket XML document that is mishandled in a
    wddx_deserialize call, as demonstrated by a stray
    element inside a boolean element, leading to incorrect
    pop processing.(CVE-2016-7132)

  - The php_wddx_pop_element function in ext/wddx/wddx.c in
    PHP before 5.6.25 and 7.x before 7.0.10 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) or possibly have
    unspecified other impact via an invalid base64 binary
    value, as demonstrated by a wddx_deserialize call that
    mishandles a binary element in a wddxPacket XML
    document.( CVE-2016-7130)

  - The imagegammacorrect function in ext/gd/gd.c in PHP
    before 5.6.25 and 7.x before 7.0.10 does not properly
    validate gamma values, which allows remote attackers to
    cause a denial of service (out-of-bounds write) or
    possibly have unspecified other impact by providing
    different signs for the second and third
    arguments.(CVE-2016-7127)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # http://developer.huawei.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1068
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a91eb782");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["php-5.4.16-42.h27",
        "php-cli-5.4.16-42.h27",
        "php-common-5.4.16-42.h27",
        "php-gd-5.4.16-42.h27",
        "php-ldap-5.4.16-42.h27",
        "php-mysql-5.4.16-42.h27",
        "php-odbc-5.4.16-42.h27",
        "php-pdo-5.4.16-42.h27",
        "php-pgsql-5.4.16-42.h27",
        "php-process-5.4.16-42.h27",
        "php-recode-5.4.16-42.h27",
        "php-soap-5.4.16-42.h27",
        "php-xml-5.4.16-42.h27",
        "php-xmlrpc-5.4.16-42.h27"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
