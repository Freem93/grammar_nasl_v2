#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:569 and 
# CentOS Errata and Security Advisory 2005:569 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21947);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-2096");
  script_osvdb_id(17827);
  script_xref(name:"RHSA", value:"2005:569");

  script_name(english:"CentOS 4 : zlib (CESA-2005:569)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Zlib packages that fix a buffer overflow are now available for
Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Zlib is a general-purpose lossless data compression library which is
used by many different programs.

Tavis Ormandy discovered a buffer overflow affecting Zlib version 1.2
and above. An attacker could create a carefully crafted compressed
stream that would cause an application to crash if the stream is
opened by a user. As an example, an attacker could create a malicious
PNG image file which would cause a web browser or mail viewer to crash
if the image is viewed. The Common Vulnerabilities and Exposures
project assigned the name CVE-2005-2096 to this issue.

Please note that the versions of Zlib as shipped with Red Hat
Enterprise Linux 2.1 and 3 are not vulnerable to this issue.

All users should update to these erratum packages which contain a
patch from Mark Adler which corrects this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011915.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d67a14e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011916.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8d7fad6c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011917.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88501899"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected zlib packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:zlib-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/07");
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
if (rpm_check(release:"CentOS-4", reference:"zlib-1.2.1.2-1.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"zlib-devel-1.2.1.2-1.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
