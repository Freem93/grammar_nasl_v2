#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0597 and 
# CentOS Errata and Security Advisory 2006:0597 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22066);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3376");
  script_osvdb_id(26961);
  script_xref(name:"RHSA", value:"2006:0597");

  script_name(english:"CentOS 4 : libwmf (CESA-2006:0597)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libwmf packages that fix a security flaw are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Libwmf is a library for reading and converting Windows MetaFile vector
graphics (WMF). Libwmf is used by packages such as The GIMP and
ImageMagick.

An integer overflow flaw was discovered in libwmf. An attacker could
create a carefully crafted WMF flaw that could execute arbitrary code
if opened by a victim. (CVE-2006-3376).

Users of libwmf should update to these packages which contain a
backported security patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013025.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9defa624"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a4d6058"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013045.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acb6d938"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwmf packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libwmf-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-4", reference:"libwmf-0.2.8.3-5.3")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libwmf-devel-0.2.8.3-5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
