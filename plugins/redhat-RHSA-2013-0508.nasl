#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0508. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64758);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:17:31 $");

  script_cve_id("CVE-2013-0219", "CVE-2013-0220");
  script_bugtraq_id(57539);
  script_osvdb_id(89540, 89541, 89542);
  script_xref(name:"RHSA", value:"2013:0508");

  script_name(english:"RHEL 6 : sssd (RHSA-2013:0508)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sssd packages that fix two security issues, multiple bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The System Security Services Daemon (SSSD) provides a set of daemons
to manage access to remote directories and authentication mechanisms.
It provides an NSS and PAM interface toward the system and a pluggable
back-end system to connect to multiple different account sources. It
is also the basis to provide client auditing and policy services for
projects such as FreeIPA.

A race condition was found in the way SSSD copied and removed user
home directories. A local attacker who is able to write into the home
directory of a different user who is being removed could use this flaw
to perform symbolic link attacks, possibly allowing them to modify and
delete arbitrary files with the privileges of the root user.
(CVE-2013-0219)

Multiple out-of-bounds memory read flaws were found in the way the
autofs and SSH service responders parsed certain SSSD packets. An
attacker could spend a specially crafted packet that, when processed
by the autofs or SSH service responders, would cause SSSD to crash.
This issue only caused a temporary denial of service, as SSSD was
automatically restarted by the monitor process after the crash.
(CVE-2013-0220)

The CVE-2013-0219 and CVE-2013-0220 issues were discovered by Florian
Weimer of the Red Hat Product Security Team.

These updated sssd packages also include numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.4
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All SSSD users are advised to upgrade to these updated packages, which
upgrade SSSD to upstream version 1.9 to correct these issues, fix
these bugs and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0219.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-0220.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/html/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?faae67f0"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0508.html"
  );
  # https://access.redhat.com/knowledge/docs/en-US/Red_Hat_Enterprise_Linux/6/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?879a0985"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_sudo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0508";
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
  if (rpm_check(release:"RHEL6", reference:"libipa_hbac-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libipa_hbac-devel-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libipa_hbac-python-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libipa_hbac-python-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libipa_hbac-python-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libsss_autofs-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libsss_autofs-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsss_autofs-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libsss_idmap-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libsss_idmap-devel-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libsss_sudo-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libsss_sudo-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libsss_sudo-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libsss_sudo-devel-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sssd-client-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"sssd-debuginfo-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"sssd-tools-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"sssd-tools-1.9.2-82.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"sssd-tools-1.9.2-82.el6")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libipa_hbac / libipa_hbac-devel / libipa_hbac-python / etc");
  }
}
