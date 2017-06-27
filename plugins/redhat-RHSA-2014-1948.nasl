#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1948. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79685);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/06 15:51:00 $");

  script_cve_id("CVE-2014-3566");
  script_bugtraq_id(70574);
  script_osvdb_id(113251);
  script_xref(name:"RHSA", value:"2014:1948");

  script_name(english:"RHEL 5 / 6 / 7 : nss, nss-util, and nss-softokn (RHSA-2014:1948) (POODLE)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss, nss-util, and nss-softokn packages that contain a patch
to mitigate the CVE-2014-3566 issue, fix a number of bugs, and add
various enhancements are now available for Red Hat Enterprise Linux 5,
6, and 7.

Red Hat Product Security has rated this update as having Important
security impact.

Network Security Services (NSS) is a set of libraries designed to
support the cross-platform development of security-enabled client and
server applications. Netscape Portable Runtime (NSPR) provides
platform independence for non-GUI operating system facilities.

This update adds support for the TLS Fallback Signaling Cipher Suite
Value (TLS_FALLBACK_SCSV), which can be used to prevent protocol
downgrade attacks against applications which re-connect using a lower
SSL/TLS protocol version when the initial connection indicating the
highest supported protocol version fails.

This can prevent a forceful downgrade of the communication to SSL 3.0.
The SSL 3.0 protocol was found to be vulnerable to the padding oracle
attack when using block cipher suites in cipher block chaining (CBC)
mode. This issue is identified as CVE-2014-3566, and also known under
the alias POODLE. This SSL 3.0 protocol flaw will not be addressed in
a future update; it is recommended that users configure their
applications to require at least TLS protocol version 1.0 for secure
communication.

For additional information about this flaw, see the Knowledgebase
article at https://access.redhat.com/articles/1232123

The nss, nss-util, and nss-softokn packages have been upgraded to
upstream version 3.16.2.3, which provides a number of bug fixes and
enhancements over the previous version, and adds the support for
Mozilla Firefox 31.3. (BZ#1158159, BZ#1165003, BZ#1165525)

Users of nss, nss-util, and nss-softokn are advised to upgrade to
these updated packages, which contain a backported patch to mitigate
the CVE-2014-3566 issue, fix these bugs, and add these enhancements.
After installing this update, applications using NSS or NSPR must be
restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://access.redhat.com/articles/1232123"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1948.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:TF/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-pkcs11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-softokn-freebl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nss-util-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x / 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1948";
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
  if (rpm_check(release:"RHEL5", reference:"nss-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-debuginfo-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-devel-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", reference:"nss-pkcs11-devel-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"nss-tools-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"nss-tools-3.16.2.3-1.el5_11")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"nss-tools-3.16.2.3-1.el5_11")) flag++;


  if (rpm_check(release:"RHEL6", reference:"nss-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-debuginfo-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-devel-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-pkcs11-devel-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-sysinit-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-sysinit-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-sysinit-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nss-tools-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nss-tools-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nss-tools-3.16.2.3-3.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-3.16.2.3-2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-debuginfo-3.16.2.3-2.el6_6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"nss-util-devel-3.16.2.3-2.el6_6")) flag++;


  if (rpm_check(release:"RHEL7", reference:"nss-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-debuginfo-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-devel-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-pkcs11-devel-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-debuginfo-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-devel-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-softokn-freebl-devel-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-sysinit-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-sysinit-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"s390x", reference:"nss-tools-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", cpu:"x86_64", reference:"nss-tools-3.16.2.3-2.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-debuginfo-3.16.2.3-1.el7_0")) flag++;

  if (rpm_check(release:"RHEL7", reference:"nss-util-devel-3.16.2.3-1.el7_0")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nss / nss-debuginfo / nss-devel / nss-pkcs11-devel / nss-softokn / etc");
  }
}
