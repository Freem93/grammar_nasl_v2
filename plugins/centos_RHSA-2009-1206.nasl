#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1206 and 
# CentOS Errata and Security Advisory 2009:1206 respectively.
#

include("compat.inc");

if (description)
{
  script_id(40533);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2414", "CVE-2009-2416");
  script_osvdb_id(56985, 56990);
  script_xref(name:"RHSA", value:"2009:1206");

  script_name(english:"CentOS 3 / 5 : libxml / libxml2 (CESA-2009:1206)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml and libxml2 packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 3, 4, and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

libxml is a library for parsing and manipulating XML files. A Document
Type Definition (DTD) defines the legal syntax (and also which
elements can be used) for certain types of files, such as XML files.

A stack overflow flaw was found in the way libxml processes the root
XML document element definition in a DTD. A remote attacker could
provide a specially crafted XML file, which once opened by a local,
unsuspecting user, would lead to denial of service (application
crash). (CVE-2009-2414)

Multiple use-after-free flaws were found in the way libxml parses the
Notation and Enumeration attribute types. A remote attacker could
provide a specially crafted XML file, which once opened by a local,
unsuspecting user, would lead to denial of service (application
crash). (CVE-2009-2416)

Users should upgrade to these updated packages, which contain
backported patches to resolve these issues. For Red Hat Enterprise
Linux 3, they contain backported patches for the libxml and libxml2
packages. For Red Hat Enterprise Linux 4 and 5, they contain
backported patches for the libxml2 packages. The desktop must be
restarted (log out, then log back in) for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016068.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69436b10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016069.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c7efd556"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016074.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8161afb7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-August/016075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d354cc1d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml and / or libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml-1.8.17-9.3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml-1.8.17-9.3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml-devel-1.8.17-9.3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml-devel-1.8.17-9.3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-2.5.10-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-2.5.10-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-devel-2.5.10-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-devel-2.5.10-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"libxml2-python-2.5.10-15")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"libxml2-python-2.5.10-15")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.2.8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.2.8")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.2.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
