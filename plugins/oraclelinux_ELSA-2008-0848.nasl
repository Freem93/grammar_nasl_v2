#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2008:0848 and 
# Oracle Linux Security Advisory ELSA-2008-0848 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67740);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:41:02 $");

  script_cve_id("CVE-2006-2193", "CVE-2008-2327");
  script_bugtraq_id(18331, 30832);
  script_xref(name:"RHSA", value:"2008:0848");

  script_name(english:"Oracle Linux 4 : libtiff (ELSA-2008-0848)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2008:0848 :

Updated libtiff packages that fix various security issues and a bug
are now available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

Multiple uses of uninitialized values were discovered in libtiff's
Lempel-Ziv-Welch (LZW) compression algorithm decoder. An attacker
could create a carefully crafted LZW-encoded TIFF file that would
cause an application linked with libtiff to crash or, possibly,
execute arbitrary code. (CVE-2008-2327)

Red Hat would like to thank Drew Yao of the Apple Product Security
team for reporting this issue.

A buffer overflow flaw was discovered in the tiff2pdf conversion
program distributed with libtiff. An attacker could create a TIFF file
containing UTF-8 characters that would, when converted to PDF format,
cause tiff2pdf to crash, or, possibly, execute arbitrary code.
(CVE-2006-2193)

Additionally, these updated packages fix the following bug :

* the libtiff packages included manual pages for the sgi2tiff and
tiffsv commands, which are not included in these packages. These
extraneous manual pages were removed.

All libtiff users are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2008-August/000723.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/29");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"libtiff-3.6.1-12.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"libtiff-devel-3.6.1-12.el4_7.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libtiff / libtiff-devel");
}
