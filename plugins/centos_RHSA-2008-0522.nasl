#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0522 and 
# CentOS Errata and Security Advisory 2008:0522 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33171);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2008-1927");
  script_bugtraq_id(28928);
  script_xref(name:"RHSA", value:"2008:0522");

  script_name(english:"CentOS 3 / 4 / 5 : perl (CESA-2008:0522)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated perl packages that fix a security issue are now available for
Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Perl is a high-level programming language commonly used for system
administration utilities and Web programming.

A flaw was found in Perl's regular expression engine. A specially
crafted regular expression with Unicode characters could trigger a
buffer overflow, causing Perl to crash, or possibly execute arbitrary
code with the privileges of the user running Perl. (CVE-2008-1927)

Users of perl are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014975.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d6f34b5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014976.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d673c909"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014982.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?346c586d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/014984.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af4158b7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015016.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2918c12c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?225cbc34"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4db05cc8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-June/015043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f47d3a3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-CGI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-CPAN");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-DB_File");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-suidperl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"perl-5.8.0-98.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-CGI-2.89-98.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-CPAN-1.61-98.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-DB_File-1.806-98.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"perl-suidperl-5.8.0-98.EL3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-5.8.5-36.el4_6.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"perl-5.8.5-36.c4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-5.8.5-36.el4_6.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-suidperl-5.8.5-36.el4_6.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"perl-suidperl-5.8.5-36.c4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-suidperl-5.8.5-36.el4_6.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"perl-5.8.8-10.el5_2.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"perl-suidperl-5.8.8-10.el5_2.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
