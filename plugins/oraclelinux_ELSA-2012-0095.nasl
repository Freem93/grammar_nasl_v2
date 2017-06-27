#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0095 and 
# Oracle Linux Security Advisory ELSA-2012-0095 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68450);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/12/01 17:07:14 $");

  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_bugtraq_id(40467, 42640, 43932);
  script_xref(name:"RHSA", value:"2012:0095");

  script_name(english:"Oracle Linux 5 / 6 : ghostscript (ELSA-2012-0095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0095 :

Updated ghostscript packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ghostscript is a set of software that provides a PostScript
interpreter, a set of C procedures (the Ghostscript library, which
implements the graphics capabilities in the PostScript language) and
an interpreter for Portable Document Format (PDF) files.

An integer overflow flaw was found in Ghostscript's TrueType bytecode
interpreter. An attacker could create a specially crafted PostScript
or PDF file that, when interpreted, could cause Ghostscript to crash
or, potentially, execute arbitrary code. (CVE-2009-3743)

It was found that Ghostscript always tried to read Ghostscript system
initialization files from the current working directory before
checking other directories, even if a search path that did not contain
the current working directory was specified with the '-I' option, or
the '-P-' option was used (to prevent the current working directory
being searched first). If a user ran Ghostscript in an
attacker-controlled directory containing a system initialization file,
it could cause Ghostscript to execute arbitrary PostScript code.
(CVE-2010-2055)

Ghostscript included the current working directory in its library
search path by default. If a user ran Ghostscript without the '-P-'
option in an attacker-controlled directory containing a specially
crafted PostScript library file, it could cause Ghostscript to execute
arbitrary PostScript code. With this update, Ghostscript no longer
searches the current working directory for library files by default.
(CVE-2010-4820)

Note: The fix for CVE-2010-4820 could possibly break existing
configurations. To use the previous, vulnerable behavior, run
Ghostscript with the '-P' option (to always search the current working
directory first).

A flaw was found in the way Ghostscript interpreted PostScript Type 1
and PostScript Type 2 font files. An attacker could create a specially
crafted PostScript Type 1 or PostScript Type 2 font file that, when
interpreted, could cause Ghostscript to crash or, potentially, execute
arbitrary code. (CVE-2010-4054)

Users of Ghostscript are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-February/002591.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-February/002596.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ghostscript packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/03");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"ghostscript-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"EL5", reference:"ghostscript-devel-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"EL5", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;

if (rpm_check(release:"EL6", reference:"ghostscript-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-devel-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"EL6", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-devel / ghostscript-doc / ghostscript-gtk");
}
