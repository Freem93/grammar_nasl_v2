#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0505 and 
# CentOS Errata and Security Advisory 2010:0505 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47703);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2007-4829");
  script_bugtraq_id(26355);
  script_xref(name:"RHSA", value:"2010:0505");

  script_name(english:"CentOS 4 / 5 : perl-Archive-Tar (CESA-2010:0505)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated perl-Archive-Tar package that fixes multiple security
issues is now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The Archive::Tar module provides a mechanism for Perl scripts to
manipulate tar archive files.

Multiple directory traversal flaws were discovered in the Archive::Tar
module. A specially crafted tar file could cause a Perl script, using
the Archive::Tar module to extract the archive, to overwrite an
arbitrary file writable by the user running the script.
(CVE-2007-4829)

This package upgrades the Archive::Tar module to version 1.39_01.
Refer to the Archive::Tar module's changes file, linked to in the
References, for a full list of changes.

Users of perl-Archive-Tar are advised to upgrade to this updated
package, which corrects these issues. All applications using the
Archive::Tar module must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016749.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5278a42a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016750.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?43e9ccc1"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?698ae642"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016814.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc020bee"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-archive-tar package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-Archive-Tar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"perl-Archive-Tar-1.39.1-1.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"perl-Archive-Tar-1.39.1-1.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"perl-Archive-Tar-1.39.1-1.el5_5.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
