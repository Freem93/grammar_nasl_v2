#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:506 and 
# CentOS Errata and Security Advisory 2005:506 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21835);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2003-0427");
  script_osvdb_id(4322);
  script_xref(name:"RHSA", value:"2005:506");

  script_name(english:"CentOS 3 / 4 : mikmod (CESA-2005:506)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mikmod packages that fix a security issue are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

MikMod is a well known MOD music file player for UNIX-based systems.

A buffer overflow bug was found in mikmod during the processing of
archive filenames. An attacker could create a malicious archive that
when opened by mikmod could result in arbitrary code execution. The
Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2003-0427 to this issue.

Users of mikmod are advised to upgrade to these erratum packages,
which contain backported security patches and are not vulnerable to
these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5955c97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b9351d07"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34b26c79"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7a1e4a8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011840.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb052ba7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dde14c21"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mikmod packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mikmod-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/06/13");
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
if (rpm_check(release:"CentOS-3", reference:"mikmod-3.1.6-22.EL3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mikmod-devel-3.1.6-22.EL3")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mikmod-3.1.6-32.EL4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mikmod-devel-3.1.6-32.EL4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
