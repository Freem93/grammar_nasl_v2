#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0137. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57969);
  script_version ("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_bugtraq_id(45678, 46941, 47168, 47169);
  script_osvdb_id(70302, 72302, 74526, 74527, 74528, 74729);
  script_xref(name:"RHSA", value:"2012:0137");

  script_name(english:"RHEL 6 : texlive (RHSA-2012:0137)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated texlive packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

TeX Live is an implementation of TeX. TeX takes a text file and a set
of formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output. The texlive packages provide
a number of utilities, including dvips.

TeX Live embeds a copy of t1lib. The t1lib library allows you to
rasterize bitmaps from PostScript Type 1 fonts. The following issues
affect t1lib code :

Two heap-based buffer overflow flaws were found in the way t1lib
processed Adobe Font Metrics (AFM) files. If a specially crafted font
file was opened by a TeX Live utility, it could cause the utility to
crash or, potentially, execute arbitrary code with the privileges of
the user running the utility. (CVE-2010-2642, CVE-2011-0433)

An invalid pointer dereference flaw was found in t1lib. A specially
crafted font file could, when opened, cause a TeX Live utility to
crash or, potentially, execute arbitrary code with the privileges of
the user running the utility. (CVE-2011-0764)

A use-after-free flaw was found in t1lib. A specially crafted font
file could, when opened, cause a TeX Live utility to crash or,
potentially, execute arbitrary code with the privileges of the user
running the utility. (CVE-2011-1553)

An off-by-one flaw was found in t1lib. A specially crafted font file
could, when opened, cause a TeX Live utility to crash or, potentially,
execute arbitrary code with the privileges of the user running the
utility. (CVE-2011-1554)

An out-of-bounds memory read flaw was found in t1lib. A specially
crafted font file could, when opened, cause a TeX Live utility to
crash. (CVE-2011-1552)

Red Hat would like to thank the Evince development team for reporting
CVE-2010-2642. Upstream acknowledges Jon Larimer of IBM X-Force as the
original reporter of CVE-2010-2642.

All users of texlive are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2642.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0433.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0764.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1552.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1553.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0137.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mendexk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-dviutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-east-asian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/16");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0137";
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
  if (rpm_check(release:"RHEL6", reference:"kpathsea-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"kpathsea-devel-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"mendexk-2.6e-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"mendexk-2.6e-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"mendexk-2.6e-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-afm-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-afm-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-afm-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-context-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-context-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-context-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", reference:"texlive-debuginfo-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-dvips-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-dvips-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-dvips-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-dviutils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-dviutils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-dviutils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-east-asian-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-east-asian-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-east-asian-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-latex-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-latex-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-latex-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-utils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-utils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-utils-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"texlive-xetex-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"texlive-xetex-2007-57.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"texlive-xetex-2007-57.el6_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kpathsea / kpathsea-devel / mendexk / texlive / texlive-afm / etc");
  }
}
