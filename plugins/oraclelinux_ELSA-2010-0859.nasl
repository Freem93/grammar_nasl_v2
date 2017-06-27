#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2010:0859 and 
# Oracle Linux Security Advisory ELSA-2010-0859 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68137);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 16:49:14 $");

  script_cve_id("CVE-2010-3702", "CVE-2010-3703", "CVE-2010-3704");
  script_bugtraq_id(43594, 43841, 43845);
  script_osvdb_id(69062, 69063, 69064);
  script_xref(name:"RHSA", value:"2010:0859");

  script_name(english:"Oracle Linux 6 : poppler (ELSA-2010-0859)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2010:0859 :

Updated poppler packages that fix three security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Poppler is a Portable Document Format (PDF) rendering library, used by
applications such as Evince.

Two uninitialized pointer use flaws were discovered in poppler. An
attacker could create a malicious PDF file that, when opened, would
cause applications that use poppler (such as Evince) to crash or,
potentially, execute arbitrary code. (CVE-2010-3702, CVE-2010-3703)

An array index error was found in the way poppler parsed PostScript
Type 1 fonts embedded in PDF documents. An attacker could create a
malicious PDF file that, when opened, would cause applications that
use poppler (such as Evince) to crash or, potentially, execute
arbitrary code. (CVE-2010-3704)

Users are advised to upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2011-February/001824.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected poppler packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-qt4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:poppler-utils");
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
if (rpm_check(release:"EL6", reference:"poppler-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-glib-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-glib-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-qt-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-qt-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-qt4-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-qt4-devel-0.12.4-3.el6_0.1")) flag++;
if (rpm_check(release:"EL6", reference:"poppler-utils-0.12.4-3.el6_0.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "poppler / poppler-devel / poppler-glib / poppler-glib-devel / etc");
}
