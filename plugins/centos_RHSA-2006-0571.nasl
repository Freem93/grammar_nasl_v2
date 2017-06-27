#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0571 and 
# CentOS Errata and Security Advisory 2006:0571 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22065);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-3082");
  script_bugtraq_id(18554);
  script_osvdb_id(26770);
  script_xref(name:"RHSA", value:"2006:0571");

  script_name(english:"CentOS 3 / 4 : gnupg (CESA-2006:0571)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated GnuPG package that fixes a security issue is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

An integer overflow flaw was found in GnuPG. An attacker could create
a carefully crafted message packet with a large length that could
cause GnuPG to crash or possibly overwrite memory when opened.
(CVE-2006-3082)

All users of GnuPG are advised to upgrade to this updated package,
which contains a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013024.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?55c7784d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013027.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5c9fb05"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013040.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5b3a675"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f7db677"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013058.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8ab920c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-July/013059.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6f79e56"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gnupg package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gnupg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/31");
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
if (rpm_check(release:"CentOS-3", reference:"gnupg-1.2.1-16")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnupg-1.2.6-5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
