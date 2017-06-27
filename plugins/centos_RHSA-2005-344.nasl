#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:344 and 
# CentOS Errata and Security Advisory 2005:344 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21807);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-0891");
  script_osvdb_id(15174, 15175);
  script_xref(name:"RHSA", value:"2005:344");

  script_name(english:"CentOS 3 / 4 : gtk2 (CESA-2005:344)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gtk2 packages that fix a double free vulnerability are now
available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The gtk2 package contains the GIMP ToolKit (GTK+), a library for
creating graphical user interfaces for the X Window System.

A bug was found in the way gtk2 processes BMP images. It is possible
that a specially crafted BMP image could cause a denial of service
attack on applications linked against gtk2. The Common Vulnerabilities
and Exposures project (cve.mitre.org) has assigned the name
CVE-2005-0891 to this issue.

Users of gtk2 are advised to upgrade to these packages, which contain
a backported patch and is not vulnerable to this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011518.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?45857983"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011519.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf484e27"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011521.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b0182ddf"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011522.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5d42269a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-April/011526.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b8e4c705"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gtk2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
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
if (rpm_check(release:"CentOS-3", reference:"gtk2-2.2.4-15")) flag++;
if (rpm_check(release:"CentOS-3", reference:"gtk2-devel-2.2.4-15")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gtk2-2.4.13-14")) flag++;
if (rpm_check(release:"CentOS-4", reference:"gtk2-devel-2.4.13-14")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
