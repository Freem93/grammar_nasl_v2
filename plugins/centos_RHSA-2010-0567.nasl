#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0567 and 
# CentOS Errata and Security Advisory 2010:0567 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47903);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/06/28 23:54:23 $");

  script_cve_id("CVE-2010-2526");
  script_osvdb_id(66753);
  script_xref(name:"RHSA", value:"2010:0567");

  script_name(english:"CentOS 5 : lvm2-cluster (CESA-2010:0567)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote CentOS host is missing a security update which has been
documented in Red Hat advisory RHSA-2010:0567."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016844.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe0cf501"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016845.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?212d8733"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected lvm2-cluster package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:lvm2-cluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"lvm2-cluster-2.02.56-7.el5_5.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
