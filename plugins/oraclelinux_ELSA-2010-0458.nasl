#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0458 and 
# Oracle Linux Security Advisory ELSA-2010-0458 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68048);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/26 16:04:31 $");

  script_cve_id("CVE-2008-5302", "CVE-2008-5303", "CVE-2010-1168", "CVE-2010-1447");
  script_bugtraq_id(12767, 40302, 40305);
  script_osvdb_id(50446, 64756, 65683);
  script_xref(name:"RHSA", value:"2010:0458");

  script_name(english:"Oracle Linux 5 : perl (ELSA-2010-0458)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0458 :

Updated perl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Perl is a high-level programming language commonly used for system
administration utilities and web programming. The Safe extension
module allows users to compile and execute Perl code in restricted
compartments. The File::Path module allows users to create and remove
directory trees.

The Safe module did not properly restrict the code of implicitly
called methods (such as DESTROY and AUTOLOAD) on implicitly blessed
objects returned as a result of unsafe code evaluation. These methods
could have been executed unrestricted by Safe when such objects were
accessed or destroyed. A specially crafted Perl script executed inside
of a Safe compartment could use this flaw to bypass intended Safe
module restrictions. (CVE-2010-1168)

The Safe module did not properly restrict code compiled in a Safe
compartment and executed out of the compartment via a subroutine
reference returned as a result of unsafe code evaluation. A specially
crafted Perl script executed inside of a Safe compartment could use
this flaw to bypass intended Safe module restrictions, if the returned
subroutine reference was called from outside of the compartment.
(CVE-2010-1447)

Multiple race conditions were found in the way the File::Path module's
rmtree function removed directory trees. A malicious, local user with
write access to a directory being removed by a victim, running a Perl
script using rmtree, could cause the permissions of arbitrary files to
be changed to world-writable and setuid, or delete arbitrary files via
a symbolic link attack, if the victim had the privileges to change the
permissions of the target files or to remove them. (CVE-2008-5302,
CVE-2008-5303)

Red Hat would like to thank Tim Bunce for responsibly reporting the
CVE-2010-1168 and CVE-2010-1447 issues. Upstream acknowledges Nick
Cleaton as the original reporter of CVE-2010-1168, and Tim Bunce and
Rafael Garcia-Suarez as the original reporters of CVE-2010-1447.

These packages upgrade the Safe extension module to version 2.27.
Refer to the Safe module's Changes file, linked to in the References,
for a full list of changes.

Users of perl are advised to upgrade to these updated packages, which
correct these issues. All applications using the Safe or File::Path
modules must be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2010-June/001491.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(362);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"perl-5.8.8-32.el5_5.1")) flag++;
if (rpm_check(release:"EL5", reference:"perl-suidperl-5.8.8-32.el5_5.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl / perl-suidperl");
}
