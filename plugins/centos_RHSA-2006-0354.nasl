#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0354 and 
# CentOS Errata and Security Advisory 2006:0354 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22274);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-1704");
  script_xref(name:"RHSA", value:"2006:0354");

  script_name(english:"CentOS 4 : elfutils (CESA-2006:0354)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated elfutils packages that address a minor security issue and
various other issues are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The elfutils packages contain a number of utility programs and
libraries related to the creation and maintenance of executable code.

The elfutils packages that originally shipped with Red Hat Enterprise
Linux 4 were GPL-licensed versions which lacked some functionality.
Previous updates provided fully functional versions of elfutils only
under the OSL license. This update provides a fully functional,
GPL-licensed version of elfutils.

In the OSL-licensed elfutils versions provided in previous updates,
some tools could sometimes crash when given corrupted input files.
(CVE-2005-1704)

Also, when the eu-strip tool was used to create separate debuginfo
files from relocatable objects such as kernel modules (.ko), the
resulting debuginfo files (.ko.debug) were sometimes corrupted. Both
of these problems are fixed in the new version.

Users of elfutils should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?858af323"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea9ec319"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f1ed4028"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elfutils packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libelf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elfutils-libelf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"elfutils-0.97.1-3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"elfutils-devel-0.97.1-3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"elfutils-libelf-0.97.1-3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"elfutils-libelf-devel-0.97.1-3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
