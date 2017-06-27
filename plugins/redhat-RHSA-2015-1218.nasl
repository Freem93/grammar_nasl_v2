#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1218. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84660);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/01/06 16:01:52 $");

  script_cve_id("CVE-2014-9425", "CVE-2014-9705", "CVE-2014-9709", "CVE-2015-0232", "CVE-2015-0273", "CVE-2015-2301", "CVE-2015-2783", "CVE-2015-2787", "CVE-2015-3307", "CVE-2015-3329", "CVE-2015-3411", "CVE-2015-3412", "CVE-2015-4021", "CVE-2015-4022", "CVE-2015-4024", "CVE-2015-4026", "CVE-2015-4147", "CVE-2015-4148", "CVE-2015-4598", "CVE-2015-4599", "CVE-2015-4600", "CVE-2015-4601", "CVE-2015-4602", "CVE-2015-4603", "CVE-2015-4643");
  script_bugtraq_id(71800, 72541, 72701, 73031, 73037, 73306, 73357, 73431, 74239, 74240, 74413, 74700, 74703, 74902, 74903, 75056, 75103, 75244, 75246, 75249, 75250, 75251, 75252, 75255);
  script_osvdb_id(116499, 117467, 117469, 118582, 118589, 119650, 119772, 119774, 120925, 120926, 120938, 121398, 122125, 122126, 122127, 122257, 122261, 123148, 123639, 123640, 123677);
  script_xref(name:"RHSA", value:"2015:1218");

  script_name(english:"RHEL 6 : php (RHSA-2015:1218)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated php packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Server.

A flaw was found in the way PHP parsed multipart HTTP POST requests. A
specially crafted request could cause PHP to use an excessive amount
of CPU time. (CVE-2015-4024)

An uninitialized pointer use flaw was found in PHP's Exif extension. A
specially crafted JPEG or TIFF file could cause a PHP application
using the exif_read_data() function to crash or, possibly, execute
arbitrary code with the privileges of the user running that PHP
application. (CVE-2015-0232)

An integer overflow flaw leading to a heap-based buffer overflow was
found in the way PHP's FTP extension parsed file listing FTP server
responses. A malicious FTP server could use this flaw to cause a PHP
application to crash or, possibly, execute arbitrary code.
(CVE-2015-4022)

Multiple flaws were discovered in the way PHP performed object
unserialization. Specially crafted input processed by the
unserialize() function could cause a PHP application to crash or,
possibly, execute arbitrary code. (CVE-2015-0273, CVE-2015-2787,
CVE-2015-4147, CVE-2015-4148, CVE-2015-4599, CVE-2015-4600,
CVE-2015-4601, CVE-2015-4602, CVE-2015-4603)

It was found that certain PHP functions did not properly handle file
names containing a NULL character. A remote attacker could possibly
use this flaw to make a PHP script access unexpected files and bypass
intended file system access restrictions. (CVE-2015-4026,
CVE-2015-3411, CVE-2015-3412, CVE-2015-4598)

Multiple flaws were found in the way the way PHP's Phar extension
parsed Phar archives. A specially crafted archive could cause PHP to
crash or, possibly, execute arbitrary code when opened.
(CVE-2015-2301, CVE-2015-2783, CVE-2015-3307, CVE-2015-3329,
CVE-2015-4021)

A heap buffer overflow flaw was found in the
enchant_broker_request_dict() function of PHP's enchant extension. An
attacker able to make a PHP application enchant dictionaries could
possibly cause it to crash. (CVE-2014-9705)

A buffer over-read flaw was found in the GD library used by the PHP gd
extension. A specially crafted GIF file could cause a PHP application
using the imagecreatefromgif() function to crash. (CVE-2014-9709)

A double free flaw was found in zend_ts_hash_graceful_destroy()
function in the PHP ZTS module. This flaw could possibly cause a PHP
application to crash. (CVE-2014-9425)

All php users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9425.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-9709.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0232.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-0273.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2301.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2783.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2787.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3307.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3329.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3411.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3412.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4022.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4148.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4599.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4600.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4601.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4602.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4603.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-4643.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1218.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-embedded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-enchant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pspell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-tidy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-zts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1218";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-bcmath-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-bcmath-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-bcmath-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-cli-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-cli-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-cli-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-common-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-common-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-common-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-dba-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-dba-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-dba-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-debuginfo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-debuginfo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-debuginfo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-devel-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-devel-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-devel-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-embedded-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-embedded-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-embedded-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-enchant-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-enchant-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-enchant-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-fpm-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-fpm-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-fpm-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-gd-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-gd-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-gd-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-imap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-imap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-imap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-intl-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-intl-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-intl-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-ldap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-ldap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-ldap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mbstring-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mbstring-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mbstring-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-mysql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-mysql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-mysql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-odbc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-odbc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-odbc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pdo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pdo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pdo-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pgsql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pgsql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pgsql-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-process-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-process-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-process-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-pspell-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-pspell-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-pspell-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-recode-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-recode-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-recode-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-snmp-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-snmp-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-snmp-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-soap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-soap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-soap-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-tidy-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-tidy-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-tidy-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xml-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xml-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xml-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-xmlrpc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-xmlrpc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-xmlrpc-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"php-zts-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"php-zts-5.3.3-46.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"php-zts-5.3.3-46.el6_6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php / php-bcmath / php-cli / php-common / php-dba / php-debuginfo / etc");
  }
}
