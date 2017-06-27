#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1419 and 
# CentOS Errata and Security Advisory 2015:1419 respectively.
#

include("compat.inc");

if (description)
{
  script_id(85019);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/07/28 16:58:13 $");

  script_cve_id("CVE-2015-1819");
  script_bugtraq_id(75570);
  script_osvdb_id(120600);
  script_xref(name:"RHSA", value:"2015:1419");

  script_name(english:"CentOS 6 : libxml2 (CESA-2015:1419)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Low security
impact. A Common Vulnerability Scoring System (CVSS) base score, which
gives a detailed severity rating, is available from the CVE link in
the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

A denial of service flaw was found in the way the libxml2 library
parsed certain XML files. An attacker could provide a specially
crafted XML file that, when parsed by an application using libxml2,
could cause that application to use an excessive amount of memory.
(CVE-2015-1819)

This issue was discovered by Florian Weimer of Red Hat Product
Security.

This update also fixes the following bug :

This update fixes an error that occurred when running a test case for
the serialization of HTML documents. (BZ#1004513)

Users of libxml2 are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-July/002030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78ce1487"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/28");
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
if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-20.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-20.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
