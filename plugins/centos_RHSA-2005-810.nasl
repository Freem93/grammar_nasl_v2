#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:810 and 
# CentOS Errata and Security Advisory 2005:810 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21866);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2017/01/04 15:13:48 $");

  script_cve_id("CVE-2005-2975", "CVE-2005-2976", "CVE-2005-3186");
  script_osvdb_id(20840, 20841, 20842);
  script_xref(name:"RHSA", value:"2005:810");

  script_name(english:"CentOS 3 / 4 : gdk-pixbuf (CESA-2005:810)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gdk-pixbuf packages that fix several security issues are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gdk-pixbuf package contains an image loading library used with the
GNOME GUI desktop environment.

A bug was found in the way gdk-pixbuf processes XPM images. An
attacker could create a carefully crafted XPM file in such a way that
it could cause an application linked with gdk-pixbuf to execute
arbitrary code when the file was opened by a victim. The Common
Vulnerabilities and Exposures project has assigned the name
CVE-2005-3186 to this issue.

Ludwig Nussel discovered an integer overflow bug in the way gdk-pixbuf
processes XPM images. An attacker could create a carefully crafted XPM
file in such a way that it could cause an application linked with
gdk-pixbuf to execute arbitrary code or crash when the file was opened
by a victim. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2005-2976 to this issue.

Ludwig Nussel also discovered an infinite-loop denial of service bug
in the way gdk-pixbuf processes XPM images. An attacker could create a
carefully crafted XPM file in such a way that it could cause an
application linked with gdk-pixbuf to stop responding when the file
was opened by a victim. The Common Vulnerabilities and Exposures
project has assigned the name CVE-2005-2975 to this issue.

Users of gdk-pixbuf are advised to upgrade to these updated packages,
which contain backported patches and are not vulnerable to these
issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012418.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52214281"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a35d9939"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012424.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?899101ec"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012425.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9089b61b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012426.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43c7c734"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-November/012428.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6099e6e7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gdk-pixbuf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gdk-pixbuf-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-0.22.0-13.el3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-devel-0.22.0-13.el3.3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gdk-pixbuf-gnome-0.22.0-13.el3.3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-0.22.0-17.el4.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gdk-pixbuf-devel-0.22.0-17.el4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
