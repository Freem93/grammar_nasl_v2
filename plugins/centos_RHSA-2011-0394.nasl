#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0394 and 
# CentOS Errata and Security Advisory 2011:0394 respectively.
#

include("compat.inc");

if (description)
{
  script_id(53504);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/06/28 23:54:24 $");

  script_cve_id("CVE-2011-0720");
  script_osvdb_id(70753);
  script_xref(name:"RHSA", value:"2011:0394");

  script_name(english:"CentOS 5 : conga (CESA-2011:0394)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2011:0394."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017419.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?64b496de"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017421.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34ac5326"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:luci");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ricci");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"luci-0.12.2-24.el5.centos.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ricci-0.12.2-24.el5.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
