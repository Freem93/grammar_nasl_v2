#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0501 and 
# CentOS Errata and Security Advisory 2007:0501 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25528);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/04 14:30:41 $");

  script_cve_id("CVE-2006-4168");
  script_bugtraq_id(24461);
  script_osvdb_id(35379);
  script_xref(name:"RHSA", value:"2007:0501");

  script_name(english:"CentOS 4 / 5 : libexif (CESA-2007:0501)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libexif packages that fix an integer overflow flaw are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The libexif package contains the EXIF library. Applications use this
library to parse EXIF image files.

An integer overflow flaw was found in the way libexif parses EXIF
image tags. If a victim opens a carefully crafted EXIF image file it
could cause the application linked against libexif to execute
arbitrary code or crash. (CVE-2007-4168)

Users of libexif should upgrade to these updated packages, which
contain a backported patch and are not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013945.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c961ebc7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013969.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76f2e542"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013970.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?626fcae0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85d27e8e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?46df5b99"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libexif packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libexif-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"libexif-0.5.12-5.1.0.2")) flag++;
if (rpm_check(release:"CentOS-4", reference:"libexif-devel-0.5.12-5.1.0.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libexif-0.6.13-4.0.2.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libexif-devel-0.6.13-4.0.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
