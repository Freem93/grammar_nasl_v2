#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0430 and 
# CentOS Errata and Security Advisory 2009:0430 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36188);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2009-0146", "CVE-2009-0147", "CVE-2009-0166", "CVE-2009-0195", "CVE-2009-0799", "CVE-2009-0800", "CVE-2009-1179", "CVE-2009-1180", "CVE-2009-1181", "CVE-2009-1182", "CVE-2009-1183");
  script_osvdb_id(54465, 54466, 54467, 54468, 54469, 54470, 54471, 54472, 54473, 54476, 54477, 54478, 54479, 54480, 54481, 54482, 54483, 54484, 54485, 54486, 54487, 54488, 54489, 54495, 54496);
  script_xref(name:"RHSA", value:"2009:0430");

  script_name(english:"CentOS 3 / 4 : xpdf (CESA-2009:0430)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated xpdf package that fixes multiple security issues is now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Xpdf is an X Window System based viewer for Portable Document Format
(PDF) files.

Multiple integer overflow flaws were found in Xpdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause Xpdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0147, CVE-2009-1179)

Multiple buffer overflow flaws were found in Xpdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause Xpdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0146, CVE-2009-1182)

Multiple flaws were found in Xpdf's JBIG2 decoder that could lead to
the freeing of arbitrary memory. An attacker could create a malicious
PDF file that would cause Xpdf to crash or, potentially, execute
arbitrary code when opened. (CVE-2009-0166, CVE-2009-1180)

Multiple input validation flaws were found in Xpdf's JBIG2 decoder. An
attacker could create a malicious PDF file that would cause Xpdf to
crash or, potentially, execute arbitrary code when opened.
(CVE-2009-0800)

Multiple denial of service flaws were found in Xpdf's JBIG2 decoder.
An attacker could create a malicious PDF that would cause Xpdf to
crash when opened. (CVE-2009-0799, CVE-2009-1181, CVE-2009-1183)

Red Hat would like to thank Braden Thomas and Drew Yao of the Apple
Product Security team, and Will Dormann of the CERT/CC for responsibly
reporting these flaws.

Users are advised to upgrade to this updated package, which contains
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015775.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67aa8a0b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015779.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65f0794b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015784.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce3b6699"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-April/015785.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8382853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015918.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2009-May/015919.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected xpdf package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(20, 119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"xpdf-2.02-14.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"xpdf-3.00-20.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
