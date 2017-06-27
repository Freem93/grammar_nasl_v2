#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0258 and 
# Oracle Linux Security Advisory ELSA-2011-0258 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68200);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:57:58 $");

  script_cve_id("CVE-2010-3315", "CVE-2010-4539", "CVE-2010-4644");
  script_bugtraq_id(43678, 45655);
  script_xref(name:"RHSA", value:"2011:0258");

  script_name(english:"Oracle Linux 6 : subversion (ELSA-2011-0258)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:0258 :

Updated subversion packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Subversion (SVN) is a concurrent version control system which enables
one or more users to collaborate in developing and maintaining a
hierarchy of files and directories while keeping a history of all
changes. The mod_dav_svn module is used with the Apache HTTP Server to
allow access to Subversion repositories via HTTP.

An access restriction bypass flaw was found in the mod_dav_svn module.
If the SVNPathAuthz directive was set to 'short_circuit', certain
access rules were not enforced, possibly allowing sensitive repository
data to be leaked to remote users. Note that SVNPathAuthz is set to
'On' by default. (CVE-2010-3315)

A server-side memory leak was found in the Subversion server. If a
malicious, remote user performed 'svn blame' or 'svn log' operations
on certain repository files, it could cause the Subversion server to
consume a large amount of system memory. (CVE-2010-4644)

A NULL pointer dereference flaw was found in the way the mod_dav_svn
module processed certain requests. If a malicious, remote user issued
a certain type of request to display a collection of Subversion
repositories on a host that has the SVNListParentPath directive
enabled, it could cause the httpd process serving the request to
crash. Note that SVNListParentPath is not enabled by default.
(CVE-2010-4539)

All Subversion users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the Subversion server must be restarted for the
update to take effect: restart httpd if you are using mod_dav_svn, or
restart svnserve if it is used."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001883.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected subversion packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-javahl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:subversion-svn2cl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"mod_dav_svn-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-devel-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-gnome-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-javahl-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-kde-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-perl-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-ruby-1.6.11-2.el6_0.2")) flag++;
if (rpm_check(release:"EL6", reference:"subversion-svn2cl-1.6.11-2.el6_0.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-devel / subversion-gnome / etc");
}
