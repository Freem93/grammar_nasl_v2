#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0615 and 
# CentOS Errata and Security Advisory 2006:0615 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22164);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-3746");
  script_bugtraq_id(19110);
  script_osvdb_id(27664);
  script_xref(name:"RHSA", value:"2006:0615");

  script_name(english:"CentOS 3 / 4 : gnupg (CESA-2006:0615)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated GnuPG packages that fix a security issue is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

GnuPG is a utility for encrypting data and creating digital
signatures.

An integer overflow flaw was found in GnuPG. An attacker could create
a carefully crafted message packet with a large length that could
cause GnuPG to crash or possibly overwrite memory when opened.
(CVE-2006-3746)

All users of GnuPG are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013106.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f2bfde1a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0a9a81e6"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013118.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f88c0b9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-August/013119.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b5c89fe"
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

  script_set_attribute(attribute:"patch_publication_date", value:"2006/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/07");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/21");
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
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"gnupg-1.2.1-17")) flag++;

if (rpm_check(release:"CentOS-4", reference:"gnupg-1.2.6-6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
