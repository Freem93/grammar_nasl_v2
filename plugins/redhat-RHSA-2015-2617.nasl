#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:2617. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87335);
  script_version("$Revision: 2.13 $");
  script_cvs_date("$Date: 2017/01/06 16:11:33 $");

  script_cve_id("CVE-2015-3194", "CVE-2015-3195", "CVE-2015-3196");
  script_osvdb_id(131038, 131039, 131040);
  script_xref(name:"RHSA", value:"2015:2617");

  script_name(english:"RHEL 6 / 7 : openssl (RHSA-2015:2617)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A NULL pointer dereference flaw was found in the way OpenSSL verified
signatures using the RSA PSS algorithm. A remote attacked could
possibly use this flaw to crash a TLS/SSL client using OpenSSL, or a
TLS/SSL server using OpenSSL if it enabled client authentication.
(CVE-2015-3194)

A memory leak vulnerability was found in the way OpenSSL parsed PKCS#7
and CMS data. A remote attacker could use this flaw to cause an
application that parses PKCS#7 or CMS data from untrusted sources to
use an excessive amount of memory and possibly crash. (CVE-2015-3195)

A race condition flaw, leading to a double free, was found in the way
OpenSSL handled pre-shared key (PSK) identify hints. A remote attacker
could use this flaw to crash a multi-threaded SSL/TLS client using
OpenSSL. (CVE-2015-3196)

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3194.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3196.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://openssl.org/news/secadv/20151203.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-2617.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/14");
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
if (! ereg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:2617";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
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
  if (rpm_check(release:"RHEL6", reference:"openssl-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-debuginfo-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", reference:"openssl-devel-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-perl-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-perl-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"openssl-static-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"openssl-static-1.0.1e-42.el6_7.1")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"openssl-static-1.0.1e-42.el6_7.1")) flag++;


  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-debuginfo-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-devel-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-libs-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"openssl-perl-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-51.el7_2.1")) flag++;

  if (rpm_check(release:"RHEL7", reference:"openssl-static-1.0.1e-51.el7_2.1")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-libs / etc");
  }
}
