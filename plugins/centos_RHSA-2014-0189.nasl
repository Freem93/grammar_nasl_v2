#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0189 and 
# CentOS Errata and Security Advisory 2014:0189 respectively.
#

include("compat.inc");

if (description)
{
  script_id(72864);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/04/28 18:05:38 $");

  script_cve_id("CVE-2013-3839", "CVE-2013-5807", "CVE-2013-5891", "CVE-2013-5908", "CVE-2014-0001", "CVE-2014-0386", "CVE-2014-0393", "CVE-2014-0401", "CVE-2014-0402", "CVE-2014-0412", "CVE-2014-0420", "CVE-2014-0437");
  script_osvdb_id(98509, 102070, 102077, 102078, 102713);
  script_xref(name:"RHSA", value:"2014:0189");

  script_name(english:"CentOS 6 : mariadb55-mariadb (CESA-2014:0189)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2014:0189."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-February/020179.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dcdd2d64"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mariadb55-mariadb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-bench");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos-scl:mariadb55-mariadb-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-5.5.35-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-bench-5.5.35-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-devel-5.5.35-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-libs-5.5.35-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-server-5.5.35-1.1.el6.centos.alt")) flag++;
if (rpm_check(release:"CentOS-6", cpu:"x86_64", reference:"mariadb55-mariadb-test-5.5.35-1.1.el6.centos.alt")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
