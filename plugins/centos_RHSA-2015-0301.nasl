#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0301 and 
# CentOS Errata and Security Advisory 2015:0301 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81886);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/07/23 14:53:34 $");

  script_cve_id("CVE-2014-9273");
  script_osvdb_id(115209);
  script_xref(name:"RHSA", value:"2015:0301");

  script_name(english:"CentOS 7 : hivex (CESA-2015:0301)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated hivex packages that fix one security issue, several bugs, and
add various enhancements are now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Hive files are undocumented binary files that Windows uses to store
the Windows Registry on disk. Hivex is a library that can read and
write to these files.

It was found that hivex attempted to read beyond its allocated buffer
when reading a hive file with a very small size or with a truncated or
improperly formatted content. An attacker able to supply a specially
crafted hive file to an application using the hivex library could
possibly use this flaw to execute arbitrary code with the privileges
of the user running that application. (CVE-2014-9273)

Red Hat would like to thank Mahmoud Al-Qudsi of NeoSmart Technologies
for reporting this issue.

The hivex package has been upgraded to upstream version 1.3.10, which
provides a number of bug fixes and enhancements over the previous
version. (BZ#1023978)

This update also fixes the following bugs :

* Due to an error in the hivex_value_data_cell_offset() function, the
hivex utility could, in some cases, print an 'Argument list is too
long' message and terminate unexpectedly when processing hive files
from the Windows Registry. This update fixes the underlying code and
hivex now processes hive files as expected. (BZ#1145056)

* A typographical error in the Win::Hivex.3pm manual page has been
corrected. (BZ#1099286)

Users of hivex are advised to upgrade to these updated packages, which
correct these issues and adds these enhancements."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-March/001583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bb101d1"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hivex packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ocaml-hivex-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:perl-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-hivex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-hivex");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ocaml-hivex-devel-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"perl-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"python-hivex-1.3.10-5.7.el7")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ruby-hivex-1.3.10-5.7.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
