#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:809 and 
# CentOS Errata and Security Advisory 2005:809 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21865);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2005-3184", "CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3245", "CVE-2005-3246", "CVE-2005-3247", "CVE-2005-3248", "CVE-2005-3249");
  script_bugtraq_id(15148, 15158, 15794);
  script_osvdb_id(20121, 20122, 20123, 20124, 20125, 20126, 20127, 20128, 20129, 20130, 20131, 20132, 20133, 20134, 20135, 20136, 20137);
  script_xref(name:"RHSA", value:"2005:809");

  script_name(english:"CentOS 3 / 4 : ethereal (CESA-2005:809)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Ethereal packages that fix various security vulnerabilities
are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The ethereal package is a program for monitoring network traffic.

A number of security flaws have been discovered in Ethereal. On a
system where Ethereal is running, a remote attacker could send
malicious packets to trigger these flaws and cause Ethereal to crash
or potentially execute arbitrary code. The Common Vulnerabilities and
Exposures project has assigned the names CVE-2005-3241, CVE-2005-3242,
CVE-2005-3243, CVE-2005-3244, CVE-2005-3245, CVE-2005-3246,
CVE-2005-3247, CVE-2005-3248, CVE-2005-3249, and CVE-2005-3184 to
these issues.

Users of ethereal should upgrade to these updated packages, which
contain version 0.10.13 and are not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012328.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6b39541"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012329.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ebb3055"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012330.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a58166f2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012331.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3655715c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012335.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?015d10e6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012336.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f562a08d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ethereal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ethereal-gnome");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"ethereal-0.10.13-1.EL3.1")) flag++;
if (rpm_check(release:"CentOS-3", reference:"ethereal-gnome-0.10.13-1.EL3.1")) flag++;

if (rpm_check(release:"CentOS-4", reference:"ethereal-0.10.13-1.EL4.1")) flag++;
if (rpm_check(release:"CentOS-4", reference:"ethereal-gnome-0.10.13-1.EL4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
