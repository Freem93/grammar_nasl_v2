#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0737. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28239);
  script_version ("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/29 15:45:03 $");

  script_cve_id("CVE-2007-1716", "CVE-2007-3102");
  script_osvdb_id(39214);
  script_xref(name:"RHSA", value:"2007:0737");

  script_name(english:"RHEL 4 : pam (RHSA-2007:0737)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pam packages that fix two security flaws, resolve two bugs,
and add an enhancement are now available for Red Hat Enterprise Linux
4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Pluggable Authentication Modules (PAM) provide a system whereby
administrators can set up authentication policies without having to
recompile programs that handle authentication.

A flaw was found in the way pam_console set console device
permissions. It was possible for various console devices to retain
ownership of the console user after logging out, possibly leaking
information to another local user. (CVE-2007-1716)

A flaw was found in the way the PAM library wrote account names to the
audit subsystem. An attacker could inject strings containing parts of
audit messages, which could possibly mislead or confuse audit log
parsing tools. (CVE-2007-3102)

As well, these updated packages fix the following bugs :

* the pam_xauth module, which is used for copying the X11
authentication cookie, did not reset the 'XAUTHORITY' variable in
certain circumstances, causing unnecessary delays when using su
command.

* when calculating password similarity, pam_cracklib disregarded
changes to the last character in passwords when 'difok=x' (where 'x'
is the number of characters required to change) was configured in
'/etc/pam.d/system-auth'. This resulted in password changes that
should have been successful to fail with the following error :

BAD PASSWORD: is too similar to the old one

This issue has been resolved in these updated packages.

* the pam_limits module, which provides setting up system resources
limits for user sessions, reset the nice priority of the user session
to '0' if it was not configured otherwise in the
'/etc/security/limits.conf' configuration file.

These updated packages add the following enhancement :

* a new PAM module, pam_tally2, which allows accounts to be locked
after a maximum number of failed log in attempts.

All users of PAM should upgrade to these updated packages, which
resolve these issues and add this enhancement."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-1716.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2007-3102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2007-0737.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pam and / or pam-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2007:0737";
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
  if (rpm_check(release:"RHEL4", reference:"pam-0.77-66.23")) flag++;
  if (rpm_check(release:"RHEL4", reference:"pam-devel-0.77-66.23")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "pam / pam-devel");
  }
}
