#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0135 and 
# CentOS Errata and Security Advisory 2008:0135 respectively.
#

include("compat.inc");

if (description)
{
  script_id(31140);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:18 $");

  script_cve_id("CVE-2007-5378", "CVE-2008-0553");
  script_bugtraq_id(27655);
  script_xref(name:"RHSA", value:"2008:0135");

  script_name(english:"CentOS 4 : tk (CESA-2008:0135)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tk packages that fix a security issue are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

[Updated 22 February 2008] The packages in this errata were originally
pushed to the wrong Red Hat Network channels and were not available to
all users. We have updated this errata with the correct channels.

Tk is a graphical toolkit for the Tcl scripting language.

An input validation flaw was discovered in Tk's GIF image handling. A
code-size value read from a GIF image was not properly validated
before being used, leading to a buffer overflow. A specially crafted
GIF file could use this to cause a crash or, potentially, execute code
with the privileges of the application using the Tk graphical toolkit.
(CVE-2008-0553)

A buffer overflow flaw was discovered in Tk's animated GIF image
handling. An animated GIF containing an initial image smaller than
subsequent images could cause a crash or, potentially, execute code
with the privileges of the application using the Tk library.
(CVE-2007-5378)

All users are advised to upgrade to these updated packages which
contain a backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014693.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0dbb0bc3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014698.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1197ecbb"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-February/014699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8870020d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tk-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tk-8.4.7-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tk-8.4.7-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tk-8.4.7-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"tk-devel-8.4.7-3.el4_6.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"tk-devel-8.4.7-3.c4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"tk-devel-8.4.7-3.el4_6.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
