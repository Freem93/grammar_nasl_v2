#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0582 and 
# CentOS Errata and Security Advisory 2006:0582 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22277);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2005-2494");
  script_osvdb_id(19220);
  script_xref(name:"RHSA", value:"2006:0582");

  script_name(english:"CentOS 4 : kdebase (CESA-2006:0582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kdebase packages that resolve several bugs are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The kdebase packages provide the core applications for KDE, the K
Desktop Environment. These core packages include the file manager
Konqueror.

Ilja van Sprundel discovered a lock file handling flaw in kcheckpass.
If the directory /var/lock is writable by a user who is allowed to run
kcheckpass, that user could gain root privileges. In Red Hat
Enterprise Linux, the /var/lock directory is not writable by users and
therefore this flaw could only have been exploited if the permissions
on that directory have been badly configured. A patch to block this
issue has been included in this update. (CVE-2005-2494)

The following bugs have also been addressed :

  - kstart --tosystray does not send the window to the
    system tray in Kicker

  - When the customer enters or selects URLs in Firefox's
    address field, the desktop freezes for a couple of
    seconds

  - fish kioslave is broken on 64-bit systems

All users of kdebase should upgrade to these updated packages, which
contain patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013159.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9177d7a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013160.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8932f3b3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc09dc7c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kdebase packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/05");
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
if (rpm_check(release:"CentOS-4", reference:"kdebase-3.3.1-5.13")) flag++;
if (rpm_check(release:"CentOS-4", reference:"kdebase-devel-3.3.1-5.13")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
