#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0095. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57822);
  script_version ("$Revision: 1.11 $");
  script_cvs_date("$Date: 2017/01/05 16:04:20 $");

  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_bugtraq_id(40467, 42640, 43932);
  script_xref(name:"RHSA", value:"2012:0095");

  script_name(english:"RHEL 5 / 6 : ghostscript (RHSA-2012:0095)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ghostscript packages that fix multiple security issues are now
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
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3743.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2055.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4054.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4820.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0095.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0095";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
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
  if (rpm_check(release:"RHEL5", reference:"ghostscript-8.70-6.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", reference:"ghostscript-devel-8.70-6.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;


  if (rpm_check(release:"RHEL6", reference:"ghostscript-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ghostscript-debuginfo-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", reference:"ghostscript-devel-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;


  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript / ghostscript-debuginfo / ghostscript-devel / etc");
  }
}
