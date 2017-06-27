#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:756 and 
# CentOS Errata and Security Advisory 2005:756 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21853);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-2693");
  script_osvdb_id(18949);
  script_xref(name:"RHSA", value:"2005:756");

  script_name(english:"CentOS 3 / 4 : cvs (CESA-2005:756)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated cvs package that fixes a security bug is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

CVS (Concurrent Version System) is a version control system.

An insecure temporary file usage was found in the cvsbug program. It
is possible that a local user could leverage this issue to execute
arbitrary instructions as the user running cvsbug. The Common
Vulnerabilities and Exposures project assigned the name CVE-2005-2693
to this issue.

All users of cvs should upgrade to this updated package, which
includes a patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012111.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba28198d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012112.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c647d896"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012115.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?994907fa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012116.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd952c3c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012120.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d9a841d2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-September/012122.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?059a14f7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cvs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cvs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/19");
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
if (rpm_check(release:"CentOS-3", reference:"cvs-1.11.2-28")) flag++;

if (rpm_check(release:"CentOS-4", reference:"cvs-1.11.17-8.RHEL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
