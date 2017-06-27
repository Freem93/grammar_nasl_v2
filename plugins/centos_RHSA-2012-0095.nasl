#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0095 and 
# CentOS Errata and Security Advisory 2012:0095 respectively.
#

include("compat.inc");

if (description)
{
  script_id(57809);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/12/16 15:13:14 $");

  script_cve_id("CVE-2009-3743", "CVE-2010-2055", "CVE-2010-4054", "CVE-2010-4820");
  script_bugtraq_id(40467, 42640, 43932);
  script_xref(name:"RHSA", value:"2012:0095");

  script_name(english:"CentOS 5 / 6 : ghostscript (CESA-2012:0095)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
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
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?96e2671b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6458e889"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ghostscript-gtk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/03");
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
if (rpm_check(release:"CentOS-5", reference:"ghostscript-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ghostscript-devel-8.70-6.el5_7.6")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ghostscript-gtk-8.70-6.el5_7.6")) flag++;

if (rpm_check(release:"CentOS-6", reference:"ghostscript-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-devel-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-doc-8.70-11.el6_2.6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ghostscript-gtk-8.70-11.el6_2.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
