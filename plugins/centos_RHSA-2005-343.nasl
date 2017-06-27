#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:343 and 
# CentOS Errata and Security Advisory 2005:343 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21806);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0891");
  script_osvdb_id(15174, 15175);
  script_xref(name:"RHSA", value:"2005:343");

  script_name(english:"CentOS 3 / 4 : gdk-pixbuf (CESA-2005:343)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf packages that fix a double free vulnerability are
now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes BMP images. It is
possible that a specially crafted BMP image could cause a denial of
service attack on applications linked against gdk-pixbuf. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-0891 to this issue.

Users of gdk-pixbuf are advised to upgrade to these packages, which
contain a backported patch and is not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011533.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6874c7fc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011534.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ba35d5b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011537.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a33cd75"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce5ed26e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011544.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f8bad85"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/31");
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
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-0.22.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-devel-0.22.0-12.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-gnome-0.22.0-12.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-0.22.0-16.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-devel-0.22.0-16.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
