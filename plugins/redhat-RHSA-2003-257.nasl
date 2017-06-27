#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2003:257. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(12415);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/28 17:44:43 $");

  script_cve_id("CVE-2002-1323", "CVE-2003-0615");
  script_xref(name:"RHSA", value:"2003:257");

  script_name(english:"RHEL 2.1 : perl (RHSA-2003:257)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Perl packages that fix a security issue in Safe.pm and a
cross-site scripting (XSS) vulnerability in CGI.pm are now available.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

Two security issues have been found in Perl that affect the Perl
packages shipped with Red Hat Enterprise Linux :

When safe.pm versions 2.0.7 and earlier are used with Perl 5.8.0 and
earlier, it is possible for an attacker to break out of safe
compartments within Safe::reval and Safe::rdo by using a redefined @_
variable. This is due to the fact that the redefined @_ variable is
not reset between successive calls. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2002-1323
to this issue.

A cross-site scripting vulnerability was discovered in the
start_form() function of CGI.pm. The vulnerability allows a remote
attacker to insert a Web script via a URL fed into the form's action
parameter. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2003-0615 to this issue.

Users of Perl are advised to upgrade to these erratum packages, which
contain Perl 5.6.1 with backported security patches correcting these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2002-1323.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2003-0615.html"
  );
  # http://marc.theaimsgroup.com/?l=bugtraq&m=105880349328877
  script_set_attribute(
    attribute:"see_also",
    value:"http://marc.info/?l=bugtraq&m=105880349328877"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs6.perl.org/rt2/Ticket/Display.html?id=17744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2003-257.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-NDBM_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:2.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2\.1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 2.1", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if (cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i386", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2003:257";
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
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-5.6.1-36.1.99ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-CGI-2.752-36.1.99ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-CPAN-1.59_54-36.1.99ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-DB_File-1.75-36.1.99ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-NDBM_File-1.75-36.1.99ent")) flag++;
  if (rpm_check(release:"RHEL2.1", cpu:"i386", reference:"perl-suidperl-5.6.1-36.1.99ent")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-CGI / perl-CPAN / perl-DB_File / perl-NDBM_File / etc");
  }
}
