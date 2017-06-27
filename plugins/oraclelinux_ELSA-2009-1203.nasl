#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:1203 and 
# Oracle Linux Security Advisory ELSA-2009-1203 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67906);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:12 $");

  script_cve_id("CVE-2009-2411");
  script_bugtraq_id(35983);
  script_osvdb_id(56856);
  script_xref(name:"RHSA", value:"2009:1203");

  script_name(english:"Oracle Linux 4 / 5 : subversion (ELSA-2009-1203)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:1203 :

Updated subversion packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes.

Matt Lewis, of Google, reported multiple heap overflow flaws in
Subversion (server and client) when parsing binary deltas. A malicious
user with commit access to a server could use these flaws to cause a
heap overflow on that server. A malicious server could use these flaws
to cause a heap overflow on a client when it attempts to checkout or
update. These heap overflows can result in a crash or, possibly,
arbitrary code execution. (CVE-2009-2411)

All Subversion users should upgrade to these updated packages, which
contain a backported patch to correct these issues. After installing
the updated packages, the Subversion server must be restarted for the
update to take effect: restart httpd if you are using mod_dav_svn, or
restart svnserve if it is used."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001108.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-August/001110.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"mod_dav_svn-1.1.4-3.0.1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"subversion-1.1.4-3.0.1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"subversion-devel-1.1.4-3.0.1.el4_8.2")) flag++;
if (rpm_check(release:"EL4", reference:"subversion-perl-1.1.4-3.0.1.el4_8.2")) flag++;

if (rpm_check(release:"EL5", reference:"mod_dav_svn-1.4.2-4.0.1.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-1.4.2-4.0.1.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-devel-1.4.2-4.0.1.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-javahl-1.4.2-4.0.1.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-perl-1.4.2-4.0.1.el5_3.1")) flag++;
if (rpm_check(release:"EL5", reference:"subversion-ruby-1.4.2-4.0.1.el5_3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-javahl / etc");
}
