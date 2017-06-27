#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1694 and 
# CentOS Errata and Security Advisory 2015:1694 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86499);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/22 14:23:03 $");

  script_cve_id("CVE-2015-4491");
  script_osvdb_id(126022);
  script_xref(name:"RHSA", value:"2015:1694");

  script_name(english:"CentOS 6 / 7 : gdk-pixbuf2 (CESA-2015:1694)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf2 packages that fix one security issue are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

gdk-pixbuf is an image loading library that can be extended by
loadable modules for new image formats. It is used by toolkits such as
GTK+ or clutter.

An integer overflow, leading to a heap-based buffer overflow, was
found in the way gdk-pixbuf, an image loading library for GNOME,
scaled certain bitmap format images. An attacker could use a specially
crafted BMP image file that, when processed by an application compiled
against the gdk-pixbuf library, would cause that application to crash
or execute arbitrary code with the permissions of the user running the
application. (CVE-2015-4491)

Red Hat would like to thank the Mozilla project for reporting this
issue. Upstream acknowledges Gustavo Grieco as the original reporter.

All gdk-pixbuf2 users are advised to upgrade to these updated
packages, which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021355.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a85f1e3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-September/021360.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?05d3e828"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"gdk-pixbuf2-2.24.1-6.el6_7")) flag++;
if (rpm_check(release:"CentOS-6", reference:"gdk-pixbuf2-devel-2.24.1-6.el6_7")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdk-pixbuf2-2.28.2-5.el7_1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"gdk-pixbuf2-devel-2.28.2-5.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
