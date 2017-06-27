#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1664. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85615);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/01/06 16:01:53 $");

  script_cve_id("CVE-2015-2721", "CVE-2015-2730");
  script_osvdb_id(124092, 124105);
  script_xref(name:"RHSA", value:"2015:1664");

  script_name(english:"RHEL 5 : nss (RHSA-2015:1664)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss packages that fix two security issues, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 5.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Network Security Services (NSS) is a set of libraries designed to
support cross-platform development of security-enabled client and
server applications.

It was found that NSS permitted skipping of the ServerKeyExchange
packet during a handshake involving ECDHE (Elliptic Curve
Diffie-Hellman key Exchange). A remote attacker could use this flaw to
bypass the forward-secrecy of a TLS/SSL connection. (CVE-2015-2721)

A flaw was found in the way NSS verified certain ECDSA (Elliptic Curve
Digital Signature Algorithm) signatures. Under certain conditions, an
attacker could use this flaw to conduct signature forgery attacks.
(CVE-2015-2730)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Karthikeyan Bhargavan as the original
reporter of CVE-2015-2721, and Watson Ladd as the original reporter of
CVE-2015-2730.

The nss packages have been upgraded to upstream version 3.19.1, which
provides a number of bug fixes and enhancements over the previous
version.

All nss users are advised to upgrade to these updated packages, which
correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2721.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2015-2730.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2015/mfsa2015-64.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.mozilla.org/security/announce/2015/mfsa2015-71.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2015-1664.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2015:1664";
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
  if (rpm_check(release:"RHEL5", reference:"nss-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"nss-debuginfo-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"nss-devel-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", reference:"nss-pkcs11-devel-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nss-tools-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nss-tools-3.19.1-1.el5_11")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nss-tools-3.19.1-1.el5_11")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-tools");
  }
}
