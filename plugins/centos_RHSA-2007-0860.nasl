#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0860 and 
# CentOS Errata and Security Advisory 2007:0860 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25949);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-4131");
  script_bugtraq_id(25417);
  script_osvdb_id(38183);
  script_xref(name:"RHSA", value:"2007:0860");

  script_name(english:"CentOS 4 / 5 : tar (CESA-2007:0860)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated tar package that fixes a path traversal flaw is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The GNU tar program saves many files together in one archive and can
restore individual files (or all of the files) from that archive.

A path traversal flaw was discovered in the way GNU tar extracted
archives. A malicious user could create a tar archive that could write
to arbitrary files to which the user running GNU tar had write access.
(CVE-2007-4131)

Red Hat would like to thank Dmitry V. Levin for reporting this issue.

Users of tar should upgrade to this updated package, which contains a
replacement backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014149.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7d895b97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014151.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?09ce8c9d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014152.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?296b5bdc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014153.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?181cce97"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-August/014154.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a8640ea4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tar package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/08/13");
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
if (rpm_check(release:"CentOS-4", reference:"tar-1.14-12.5.1.RHEL4")) flag++;

if (rpm_check(release:"CentOS-5", reference:"tar-1.15.1-23.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
