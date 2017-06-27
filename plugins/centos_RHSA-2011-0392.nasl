#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0392 and 
# CentOS Errata and Security Advisory 2011:0392 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53239);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/24 13:36:52 $");

  script_cve_id("CVE-2011-1167");
  script_bugtraq_id(46951);
  script_osvdb_id(71256);
  script_xref(name:"RHSA", value:"2011:0392");

  script_name(english:"CentOS 4 / 5 : libtiff (CESA-2011:0392)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libtiff packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 4, 5, and 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The libtiff packages contain a library of functions for manipulating
Tagged Image File Format (TIFF) files.

A heap-based buffer overflow flaw was found in the way libtiff
processed certain TIFF files encoded with a 4-bit run-length encoding
scheme from ThunderScan. An attacker could use this flaw to create a
specially crafted TIFF file that, when opened, would cause an
application linked against libtiff to crash or, possibly, execute
arbitrary code. (CVE-2011-1167)

This update also fixes the following bug :

* The RHSA-2011:0318 libtiff update introduced a regression that
prevented certain TIFF Internet Fax image files, compressed with the
CCITT Group 4 compression algorithm, from being read. (BZ#688825)

All libtiff users should upgrade to these updated packages, which
contain a backported patch to resolve these issues. All running
applications linked against libtiff must be restarted for this update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017363.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e98468ec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017364.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c432f17"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-March/017277.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ddf5aea1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libtiff packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtiff-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtiff-3.6.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtiff-3.6.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"libtiff-devel-3.6.1-18.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"libtiff-devel-3.6.1-18.el4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libtiff-3.8.2-7.el5_6.7")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtiff-devel-3.8.2-7.el5_6.7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
