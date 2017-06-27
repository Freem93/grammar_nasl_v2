#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0340 and 
# CentOS Errata and Security Advisory 2009:0340 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35768);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/09/24 14:11:59 $");

  script_cve_id("CVE-2009-0040");
  script_bugtraq_id(33827);
  script_xref(name:"RHSA", value:"2009:0340");

  script_name(english:"CentOS 3 : libpng (CESA-2009:0340)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libpng and libpng10 packages that fix a security issue are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libpng packages contain a library of functions for creating and
manipulating PNG (Portable Network Graphics) image format files.

A flaw was discovered in libpng that could result in libpng trying to
free() random memory if certain, unlikely error conditions occurred.
If a carefully-crafted PNG file was loaded by an application linked
against libpng, it could cause the application to crash or,
potentially, execute arbitrary code with the privileges of the user
running the application. (CVE-2009-0040)

Users of libpng and libpng10 should upgrade to these updated packages,
which contain backported patches to correct these issues. All running
applications using libpng or libpng10 must be restarted for the update
to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015649.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30084045"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015650.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?479a7bba"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-March/015658.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2605ee4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libpng packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libpng10-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"libpng-1.2.2-29")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng-devel-1.2.2-29")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-1.0.13-20")) flag++;
if (rpm_check(release:"CentOS-3", reference:"libpng10-devel-1.0.13-20")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
