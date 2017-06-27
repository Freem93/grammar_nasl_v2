#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0932 and 
# CentOS Errata and Security Advisory 2007:0932 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43653);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-4897");
  script_osvdb_id(41647);
  script_xref(name:"RHSA", value:"2007:0932");

  script_name(english:"CentOS 5 : pwlib (CESA-2007:0932)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pwlib packages that fix a security issue are now available for
Red Hat Enterprise Linux 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PWLib is a library used to support cross-platform applications.

In Red Hat Enterprise Linux 5, the Ekiga teleconferencing application
uses PWLib.

A memory management flaw was discovered in PWLib. An attacker could
use this flaw to crash an application, such as Ekiga, which is linked
with pwlib (CVE-2007-4897).

Users should upgrade to these updated packages which contain a
backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?71b317cd"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014289.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb2bbfa3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pwlib packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pwlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pwlib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"pwlib-1.10.1-7.0.1.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"pwlib-devel-1.10.1-7.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
