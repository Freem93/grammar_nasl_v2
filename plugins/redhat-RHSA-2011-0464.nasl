#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0464. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53525);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/04 16:02:22 $");

  script_cve_id("CVE-2011-1094", "CVE-2011-1168");
  script_bugtraq_id(46789, 47304);
  script_xref(name:"RHSA", value:"2011:0464");

  script_name(english:"RHEL 6 : kdelibs (RHSA-2011:0464)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdelibs packages that fix two security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The kdelibs packages provide libraries for the K Desktop Environment
(KDE).

A cross-site scripting (XSS) flaw was found in the way KHTML, the HTML
layout engine used by KDE applications such as the Konqueror web
browser, displayed certain error pages. A remote attacker could use
this flaw to perform a cross-site scripting attack against victims by
tricking them into visiting a specially crafted URL. (CVE-2011-1168)

A flaw was found in the way kdelibs checked the user specified
hostname against the name in the server's SSL certificate. A
man-in-the-middle attacker could use this flaw to trick an application
using kdelibs into mistakenly accepting a certificate as if it was
valid for the host, if that certificate was issued for an IP address
to which the user specified hostname was resolved to. (CVE-2011-1094)

Note: As part of the fix for CVE-2011-1094, this update also
introduces stricter handling for wildcards used in servers' SSL
certificates.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1168.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2011-0464.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2011:0464";
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
  if (rpm_check(release:"RHEL6", reference:"kdelibs-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kdelibs-apidocs-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"kdelibs-common-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"kdelibs-common-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"kdelibs-common-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kdelibs-debuginfo-4.3.4-11.el6_0.2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kdelibs-devel-4.3.4-11.el6_0.2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-apidocs / kdelibs-common / kdelibs-debuginfo / etc");
  }
}
