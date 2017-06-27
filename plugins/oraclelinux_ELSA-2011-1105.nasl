#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:1105 and 
# Oracle Linux Security Advisory ELSA-2011-1105 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68318);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2011-2501", "CVE-2011-2690", "CVE-2011-2692");
  script_bugtraq_id(48474, 48660);
  script_osvdb_id(73493, 73982, 73984);
  script_xref(name:"RHSA", value:"2011:1105");

  script_name(english:"Oracle Linux 6 : libpng (ELSA-2011-1105)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2011:1105 :

Updated libpng packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A buffer overflow flaw was found in the way libpng processed certain
PNG image files. An attacker could create a specially crafted PNG
image that, when opened, could cause an application using libpng to
crash or, potentially, execute arbitrary code with the privileges of
the user running the application. (CVE-2011-2690)

Note: The application behavior required to exploit CVE-2011-2690 is
rarely used. No application shipped with Red Hat Enterprise Linux
behaves this way, for example.

An out-of-bounds memory read flaw was found in the way libpng
processed certain PNG image files. An attacker could create a
specially crafted PNG image that, when opened, could cause an
application using libpng to crash. (CVE-2011-2501)

An uninitialized memory read issue was found in the way libpng
processed certain PNG images that use the Physical Scale (sCAL)
extension. An attacker could create a specially crafted PNG image
that, when opened, could cause an application using libpng to crash.
(CVE-2011-2692)

Users of libpng should upgrade to these updated packages, which
upgrade libpng to version 1.2.46 to correct these issues. All running
applications using libpng must be restarted for the update to take
effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-July/002249.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libpng-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/28");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"libpng-1.2.46-1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"libpng-devel-1.2.46-1.el6_1")) flag++;
if (rpm_check(release:"EL6", reference:"libpng-static-1.2.46-1.el6_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpng / libpng-devel / libpng-static");
}
