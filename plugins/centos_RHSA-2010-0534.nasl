#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0534 and 
# CentOS Errata and Security Advisory 2010:0534 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47741);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/03 14:54:57 $");

  script_cve_id("CVE-2009-2042", "CVE-2010-0205", "CVE-2010-1205", "CVE-2010-2249");
  script_bugtraq_id(35233, 38478, 41174);
  script_osvdb_id(65852);
  script_xref(name:"RHSA", value:"2010:0534");

  script_name(english:"CentOS 3 / 4 / 5 : libpng / libpng10 (CESA-2010:0534)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng and libpng10 packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 3, 4, and 5.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A memory corruption flaw was found in the way applications, using the
libpng library and its progressive reading method, decoded certain PNG
images. An attacker could create a specially crafted PNG image that,
when opened, could cause an application using libpng to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2010-1205)

A denial of service flaw was found in the way applications using the
libpng library decoded PNG images that have certain, highly compressed
ancillary chunks. An attacker could create a specially crafted PNG
image that could cause an application using libpng to consume
excessive amounts of memory and CPU time, and possibly crash.
(CVE-2010-0205)

A memory leak flaw was found in the way applications using the libpng
library decoded PNG images that use the Physical Scale (sCAL)
extension. An attacker could create a specially crafted PNG image that
could cause an application using libpng to exhaust all available
memory and possibly crash or exit. (CVE-2010-2249)

A sensitive information disclosure flaw was found in the way
applications using the libpng library processed 1-bit interlaced PNG
images. An attacker could create a specially crafted PNG image that
could cause an application using libpng to disclose uninitialized
memory. (CVE-2009-2042)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications using libpng or libpng10 must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016918.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d98145ac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016919.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?943e2740"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016781.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51928e56"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016782.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7de5354"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016795.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?efec0873"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016796.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?055d7efe"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016809.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9ebe2a14"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016810.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2321b5d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng and / or libpng10 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libpng-1.2.2-30")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libpng-1.2.2-30")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libpng-devel-1.2.2-30")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libpng-devel-1.2.2-30")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libpng10-1.0.13-21")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libpng10-1.0.13-21")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libpng10-devel-1.0.13-21")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libpng10-devel-1.0.13-21")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng-devel-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng-devel-1.2.7-3.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-1.0.16-3.el4_8.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-1.0.16-3.el4_8.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libpng10-devel-1.0.16-3.el4_8.4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libpng10-devel-1.0.16-3.el4_8.4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libpng-1.2.10-7.1.el5_5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libpng-devel-1.2.10-7.1.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
