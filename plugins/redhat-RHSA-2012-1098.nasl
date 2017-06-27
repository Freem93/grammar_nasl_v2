#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:1098. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60058);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/05 16:04:22 $");

  script_cve_id("CVE-2012-3404", "CVE-2012-3405", "CVE-2012-3406");
  script_bugtraq_id(54374);
  script_osvdb_id(88150);
  script_xref(name:"RHSA", value:"2012:1098");

  script_name(english:"RHEL 6 : glibc (RHSA-2012:1098)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated glibc packages that fix three security issues and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The glibc packages provide the standard C and standard math libraries
used by multiple programs on the system. Without these libraries, the
Linux system cannot function properly.

Multiple errors in glibc's formatted printing functionality could
allow an attacker to bypass FORTIFY_SOURCE protections and execute
arbitrary code using a format string flaw in an application, even
though these protections are expected to limit the impact of such
flaws to an application abort. (CVE-2012-3404, CVE-2012-3405,
CVE-2012-3406)

This update also fixes the following bug :

* A programming error caused an internal array of nameservers to be
only partially initialized when the /etc/resolv.conf file contained
IPv6 nameservers. Depending on the contents of a nearby structure,
this could cause certain applications to terminate unexpectedly with a
segmentation fault. The programming error has been fixed, which
restores proper behavior with IPv6 nameservers listed in the
/etc/resolv.conf file. (BZ#837026)

All users of glibc are advised to upgrade to these updated packages,
which contain backported patches to fix these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3404.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3405.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-3406.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-1098.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:1098";
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
  if (rpm_check(release:"RHEL6", reference:"glibc-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-common-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-common-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-common-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-debuginfo-common-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-devel-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-headers-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-headers-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-headers-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"glibc-static-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"glibc-utils-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"glibc-utils-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"glibc-utils-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"nscd-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"nscd-2.12-1.80.el6_3.3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"nscd-2.12-1.80.el6_3.3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-common / glibc-debuginfo / glibc-debuginfo-common / etc");
  }
}
