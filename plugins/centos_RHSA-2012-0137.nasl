#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0137 and 
# CentOS Errata and Security Advisory 2012:0137 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57982);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2010-2642", "CVE-2011-0433", "CVE-2011-0764", "CVE-2011-1552", "CVE-2011-1553", "CVE-2011-1554");
  script_bugtraq_id(45678, 46941, 47168, 47169);
  script_osvdb_id(70302, 72302, 74526, 74527, 74528, 74729);
  script_xref(name:"RHSA", value:"2012:0137");

  script_name(english:"CentOS 6 : texlive (CESA-2012:0137)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018439.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1502355"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected texlive packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kpathsea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kpathsea-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mendexk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-afm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-context");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dvips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-dviutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-east-asian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-latex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:texlive-xetex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"kpathsea-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"kpathsea-devel-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"mendexk-2.6e-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-afm-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-context-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-dvips-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-dviutils-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-east-asian-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-latex-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-utils-2007-57.el6_2")) flag++;
if (rpm_check(release:"CentOS-6", reference:"texlive-xetex-2007-57.el6_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
