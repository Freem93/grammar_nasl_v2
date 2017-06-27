#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0400. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46309);
  script_version ("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/01/04 15:51:47 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0791", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183", "CVE-2009-3608", "CVE-2009-3609", "CVE-2010-0739", "CVE-2010-0829", "CVE-2010-1440");
  script_bugtraq_id(34568, 34791, 35195, 36703, 39500, 39966, 39969);
  script_xref(name:"RHSA", value:"2010:0400");

  script_name(english:"RHEL 5 : tetex (RHSA-2010:0400)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tetex packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

teTeX is an implementation of TeX. TeX takes a text file and a set of
formatting commands as input, and creates a typesetter-independent
DeVice Independent (DVI) file as output.

Multiple integer overflow flaws were found in the way teTeX processed
special commands when converting DVI files into PostScript. An
attacker could create a malicious DVI file that would cause the dvips
executable to crash or, potentially, execute arbitrary code.
(CVE-2010-0739, CVE-2010-1440)

Multiple array index errors were found in the way teTeX converted DVI
files into the Portable Network Graphics (PNG) format. An attacker
could create a malicious DVI file that would cause the dvipng
executable to crash. (CVE-2010-0829)

teTeX embeds a copy of Xpdf, an open source Portable Document Format
(PDF) file viewer, to allow adding images in PDF format to the
generated PDF documents. The following issues affect Xpdf code :

Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0147, CVE-2009-1179)

Multiple integer overflow flaws were found in Xpdf. If a local user
generated a PDF file from a TeX document, referencing a specially
crafted PDF file, it would cause Xpdf to crash or, potentially,
execute arbitrary code with the privileges of the user running
pdflatex. (CVE-2009-0791, CVE-2009-3608, CVE-2009-3609)

A heap-based buffer overflow flaw was found in Xpdf's JBIG2 decoder.
If a local user generated a PDF file from a TeX document, referencing
a specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0195)

Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to
the freeing of arbitrary memory. If a local user generated a PDF file
from a TeX document, referencing a specially crafted PDF file, it
would cause Xpdf to crash or, potentially, execute arbitrary code with
the privileges of the user running pdflatex. (CVE-2009-0166,
CVE-2009-1180)

Multiple input validation flaws were found in Xpdf's JBIG2 decoder. If
a local user generated a PDF file from a TeX document, referencing a
specially crafted PDF file, it would cause Xpdf to crash or,
potentially, execute arbitrary code with the privileges of the user
running pdflatex. (CVE-2009-0800)

Multiple denial of service flaws were found in Xpdf's JBIG2 decoder.
If a local user generated a PDF file from a TeX document, referencing
a specially crafted PDF file, it would cause Xpdf to crash.
(CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple
Product Security team, Will Dormann of the CERT/CC, Alin Rad Pop of
Secunia Research, and Chris Rohlf, for responsibly reporting the Xpdf
flaws.

All users of tetex are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0146.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0147.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0791.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0799.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-0800.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1179.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1180.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1181.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1182.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-1183.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3608.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2009-3609.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0739.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-0829.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1440.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0400.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-fonts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:tetex-xdvi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0400";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-afm-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-afm-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-afm-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-doc-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-doc-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-doc-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-dvips-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-dvips-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-dvips-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-fonts-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-fonts-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-fonts-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-latex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-latex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-latex-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"tetex-xdvi-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"s390x", reference:"tetex-xdvi-3.0-33.8.el5_5.5")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"tetex-xdvi-3.0-33.8.el5_5.5")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tetex / tetex-afm / tetex-doc / tetex-dvips / tetex-fonts / etc");
  }
}
