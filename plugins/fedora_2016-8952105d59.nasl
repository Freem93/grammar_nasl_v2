#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-8952105d59.
#

include("compat.inc");

if (description)
{
  script_id(92125);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/07/14 15:07:58 $");

  script_cve_id("CVE-2015-7503");
  script_xref(name:"FEDORA", value:"2016-8952105d59");

  script_name(english:"Fedora 23 : php-ZendFramework2 / php-zendframework-zendxml (2016-8952105d59)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"## 2.4.10 (2016-05-09)

  - Fix HeaderValue throwing an exception on legal
    characters

## 2.4.9 (2015-11-23)

### SECURITY UPDATES

  - **ZF2015-09**: `Zend\Captcha\Word` generates a 'word'
    for a CAPTCHA challenge by selecting a sequence of
    random letters from a character set. Prior to this
    vulnerability announcement, the selection was performed
    using PHP's internal `array_rand()` function. This
    function does not generate sufficient entropy due to its
    usage of `rand()` instead of more cryptographically
    secure methods such as `openssl_pseudo_random_bytes()`.
    This could potentially lead to information disclosure
    should an attacker be able to brute force the random
    number generation. This release contains a patch that
    replaces the `array_rand()` calls to use
    `Zend\Math\Rand::getInteger()`, which provides better
    RNG.

  - **ZF2015-10**: `Zend\Crypt\PublicKey\Rsa\PublicKey` has
    a call to `openssl_public_encrypt()` which used PHP's
    default `$padding` argument, which specifies
    `OPENSSL_PKCS1_PADDING`, indicating usage of PKCS1v1.5
    padding. This padding has a known vulnerability, the
    [Bleichenbacher's chosen-ciphertext
    attack](http://crypto.stackexchange.com/questions/12688/
    can-you-explain-bleichenbachers-cca-attack-on-pkcs1-v1-5
    ), which can be used to recover an RSA private key. This
    release contains a patch that changes the padding
    argument to use `OPENSSL_PKCS1_OAEP_PADDING`.

    Users upgrading to this version may have issues
    decrypting previously stored values, due to the change
    in padding. If this occurs, you can pass the constant
    `OPENSSL_PKCS1_PADDING` to a new `$padding` argument in
    `Zend\Crypt\PublicKey\Rsa::encrypt()` and `decrypt()`
    (though typically this should only apply to the 
latter) :

    ```php $decrypted = $rsa->decrypt($data, $key, $mode,
    OPENSSL_PKCS1_PADDING); ```

    where `$rsa` is an instance of
    `Zend\Crypt\PublicKey\Rsa`.

    (The `$key` and `$mode` argument defaults are `null` and
    `Zend\Crypt\PublicKey\Rsa::MODE_AUTO`, if you were not
    using them previously.)

    We recommend re-encrypting any such values using the new
    defaults.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-8952105d59"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-ZendFramework2 and / or
php-zendframework-zendxml packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ZendFramework2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-zendframework-zendxml");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC23", reference:"php-ZendFramework2-2.4.10-1.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"php-zendframework-zendxml-1.0.2-2.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-ZendFramework2 / php-zendframework-zendxml");
}
