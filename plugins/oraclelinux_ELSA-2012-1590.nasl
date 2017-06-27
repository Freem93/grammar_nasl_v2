#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1590 and 
# Oracle Linux Security Advisory ELSA-2012-1590 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68667);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581");
  script_bugtraq_id(54601, 55673, 56372, 56715);
  script_osvdb_id(84090, 86548, 86878, 88155);
  script_xref(name:"RHSA", value:"2012:1590");

  script_name(english:"Oracle Linux 5 / 6 : libtiff (ELSA-2012-1590)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1590 :

Updated libtiff packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

A heap-based buffer overflow flaw was found in the way libtiff
processed certain TIFF images using the Pixar Log Format encoding. An
attacker could create a specially crafted TIFF file that, when opened,
could cause an application using libtiff to crash or, possibly,
execute arbitrary code with the privileges of the user running the
application. (CVE-2012-4447)

A stack-based buffer overflow flaw was found in the way libtiff
handled DOTRANGE tags. An attacker could use this flaw to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2012-5581)

A heap-based buffer overflow flaw was found in the tiff2pdf tool. An
attacker could use this flaw to create a specially crafted TIFF file
that would cause tiff2pdf to crash or, possibly, execute arbitrary
code. (CVE-2012-3401)

A missing return value check flaw, leading to a heap-based buffer
overflow, was found in the ppm2tiff tool. An attacker could use this
flaw to create a specially crafted PPM (Portable Pixel Map) file that
would cause ppm2tiff to crash or, possibly, execute arbitrary code.
(CVE-2012-4564)

The CVE-2012-5581, CVE-2012-3401, and CVE-2012-4564 issues were
discovered by Huzaifa Sidhpurwala of the Red Hat Security Response
Team.

All libtiff users should upgrade to these updated packages, which
contain backported patches to resolve these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-December/003171.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-December/003172.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/19");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"libtiff-3.8.2-18.el5_8")) flag++;
if (rpm_check(release:"EL5", reference:"libtiff-devel-3.8.2-18.el5_8")) flag++;

if (rpm_check(release:"EL6", reference:"libtiff-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libtiff-devel-3.9.4-9.el6_3")) flag++;
if (rpm_check(release:"EL6", reference:"libtiff-static-3.9.4-9.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel / libtiff-static");
}
