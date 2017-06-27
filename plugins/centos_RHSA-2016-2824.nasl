#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:2824 and 
# CentOS Errata and Security Advisory 2016:2824 respectively.
#

include("compat.inc");

if (description)
{
  script_id(95373);
  script_version("$Revision: 3.3 $");
  script_cvs_date("$Date: 2016/12/07 20:46:53 $");

  script_cve_id("CVE-2016-0718");
  script_osvdb_id(138680);
  script_xref(name:"RHSA", value:"2016:2824");

  script_name(english:"CentOS 6 / 7 : expat (CESA-2016:2824)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for expat is now available for Red Hat Enterprise Linux 6
and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Expat is a C library for parsing XML documents.

Security Fix(es) :

* An out-of-bounds read flaw was found in the way Expat processed
certain input. A remote attacker could send specially crafted XML
that, when parsed by an application using the Expat library, would
cause that application to crash or, possibly, execute arbitrary code
with the permission of the user running the application.
(CVE-2016-0718)

Red Hat would like to thank Gustavo Grieco for reporting this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-November/022162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e7ad432"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-November/003690.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6c8d5eb"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected expat packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:expat-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"expat-2.0.1-13.el6_8")) flag++;
if (rpm_check(release:"CentOS-6", reference:"expat-devel-2.0.1-13.el6_8")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"expat-2.1.0-10.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"expat-devel-2.1.0-10.el7_3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"expat-static-2.1.0-10.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
