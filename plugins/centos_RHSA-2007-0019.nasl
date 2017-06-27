#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0019 and 
# CentOS Errata and Security Advisory 2007:0019 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24287);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2007-0010");
  script_osvdb_id(31621);
  script_xref(name:"RHSA", value:"2007:0019");

  script_name(english:"CentOS 4 : gtk2 (CESA-2007:0019)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gtk2 packages that fix a security issue are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gtk2 package contains the GIMP ToolKit (GTK+), a library for
creating graphical user interfaces for the X Window System.

A bug was found in the way the gtk2 GdkPixbufLoader() function
processed invalid input. Applications linked against gtk2 could crash
if they loaded a malformed image file. (CVE-2007-0010)

Users of gtk2 are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013481.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cda0647d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013483.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a6ef04e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-January/013484.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33bb37bb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gtk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"gtk2-2.4.13-22")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gtk2-devel-2.4.13-22")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
