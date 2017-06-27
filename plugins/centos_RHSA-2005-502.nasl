#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:502 and 
# CentOS Errata and Security Advisory 2005:502 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21941);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1760");
  script_osvdb_id(17302);
  script_xref(name:"RHSA", value:"2005:502");

  script_name(english:"CentOS 3 / 4 : sysreport (CESA-2005:502)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sysreport package that fixes an information disclosure flaw
is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team

Sysreport is a utility that gathers information about a system's
hardware and configuration. The information can then be used for
diagnostic purposes and debugging.

When run by the root user, sysreport includes the contents of the
/etc/sysconfig/rhn/up2date configuration file. If up2date has been
configured to connect to a proxy server that requires an
authentication password, that password is included in plain text in
the system report. The Common Vulnerabilities and Exposures project
assigned the name CVE-2005-1760 to this issue.

Users of sysreport should update to this erratum package, which
contains a patch that removes any proxy authentication passwords."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a70bde8c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2892e47c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7cbc24d4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a1d6140"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?069dae33"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?964b7a1e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sysreport package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sysreport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/13");
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
if (rpm_check(release:"CentOS-3", reference:"sysreport-1.3.7.2-6")) flag++;

if (rpm_check(release:"CentOS-4", reference:"sysreport-1.3.15-2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
