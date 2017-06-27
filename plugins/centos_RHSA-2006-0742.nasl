#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0742 and 
# CentOS Errata and Security Advisory 2006:0742 respectively.
#

include("compat.inc");

if (description)
{
  script_id(37097);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-5925");
  script_osvdb_id(30437);
  script_xref(name:"RHSA", value:"2006:0742");

  script_name(english:"CentOS 4 : elinks (CESA-2006:0742)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated elinks package that corrects a security vulnerability is
now available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Elinks is a text mode Web browser used from the command line that
supports rendering modern web pages.

An arbitrary file access flaw was found in the Elinks SMB protocol
handler. A malicious web page could have caused Elinks to read or
write files with the permissions of the user running Elinks.
(CVE-2006-5925)

All users of Elinks are advised to upgrade to this updated package,
which resolves this issue by removing support for the SMB protocol
from Elinks.

Note: this issue did not affect the Elinks package shipped with Red
Hat Enterprise Linux 3, or the Links package shipped with Red Hat
Enterprise Linux 2.1."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013412.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?976f3469"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013413.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a3ba443d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?13691edc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected elinks package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:elinks");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"elinks-0.9.2-3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
