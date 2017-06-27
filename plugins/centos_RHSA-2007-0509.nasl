#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0509 and 
# CentOS Errata and Security Advisory 2007:0509 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25576);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-3257");
  script_bugtraq_id(24567);
  script_osvdb_id(37489);
  script_xref(name:"RHSA", value:"2007:0509");

  script_name(english:"CentOS 3 / 4 : evolution (CESA-2007:0509)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated evolution packages that fix a security bug are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Evolution is the GNOME collection of personal information management
(PIM) tools.

A flaw was found in the way Evolution processes certain IMAP server
messages. If a user can be tricked into connecting to a malicious IMAP
server it may be possible to execute arbitrary code as the user
running evolution. (CVE-2007-3257)

All users of Evolution should upgrade to these updated packages, which
contain a backported patch which resolves this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013972.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a7dd9602"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013973.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d434929"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013978.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab54672c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/013979.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64e6998c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/014005.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c4c8ec6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-June/014008.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adeb50b2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:evolution-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/27");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/19");
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
if (rpm_check(release:"CentOS-3", reference:"evolution-1.4.5-21.el3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"evolution-devel-1.4.5-21.el3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"evolution-2.0.2-35.0.4.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"evolution-devel-2.0.2-35.0.4.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
