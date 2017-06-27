#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0305. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89071);
  script_version("$Revision: 2.15 $");
  script_cvs_date("$Date: 2017/01/10 20:34:12 $");

  script_cve_id("CVE-2015-3197", "CVE-2016-0800");
  script_osvdb_id(133715, 135149);
  script_xref(name:"RHSA", value:"2016:0305");

  script_name(english:"RHEL 6 / 7 : openssl (RHSA-2016:0305) (DROWN)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.6 and 7.1 Extended Update
Support.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

A padding oracle flaw was found in the Secure Sockets Layer version
2.0 (SSLv2) protocol. An attacker can potentially use this flaw to
decrypt RSA-encrypted cipher text from a connection using a newer
SSL/TLS protocol version, allowing them to decrypt such connections.
This cross-protocol attack is publicly referred to as DROWN.
(CVE-2016-0800)

Note: This issue was addressed by disabling the SSLv2 protocol by
default when using the 'SSLv23' connection methods, and removing
support for weak SSLv2 cipher suites. For more information, refer to
the knowledge base article linked to in the References section.

A flaw was found in the way malicious SSLv2 clients could negotiate
SSLv2 ciphers that have been disabled on the server. This could result
in weak SSLv2 ciphers being used for SSLv2 connections, making them
vulnerable to man-in-the-middle attacks. (CVE-2015-3197)

Red Hat would like to thank the OpenSSL project for reporting these
issues. Upstream acknowledges Nimrod Aviram and Sebastian Schinzel as
the original reporters.

All openssl users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library must
be restarted, or the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-3197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-0800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/2176731"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://drownattack.com/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://openssl.org/news/secadv/20160128.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://openssl.org/news/secadv/20160301.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2016-0305.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:X/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(6\.6|7\.1)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.6 / 7.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2016:0305";
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
  if (rpm_check(release:"RHEL6", sp:"6", reference:"openssl-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"openssl-debuginfo-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", reference:"openssl-devel-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"openssl-perl-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"openssl-perl-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"openssl-perl-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"i686", reference:"openssl-static-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"s390x", reference:"openssl-static-1.0.1e-30.el6_6.12")) flag++;
  if (rpm_check(release:"RHEL6", sp:"6", cpu:"x86_64", reference:"openssl-static-1.0.1e-30.el6_6.12")) flag++;

  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"openssl-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"openssl-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"openssl-debuginfo-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"openssl-devel-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"openssl-libs-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"s390x", reference:"openssl-perl-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", cpu:"x86_64", reference:"openssl-perl-1.0.1e-42.el7_1.10")) flag++;
  if (rpm_check(release:"RHEL7", sp:"1", reference:"openssl-static-1.0.1e-42.el7_1.10")) flag++;

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
