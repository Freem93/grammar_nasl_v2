#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1764 and 
# CentOS Errata and Security Advisory 2013:1764 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79176);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/01/14 15:38:18 $");

  script_cve_id("CVE-2013-4164");
  script_bugtraq_id(63873);
  script_osvdb_id(100113);
  script_xref(name:"RHSA", value:"2013:1764");

  script_name(english:"CentOS 6 : ruby (CESA-2013:1764)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix one security issue are now available
for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to perform system
management tasks.

A buffer overflow flaw was found in the way Ruby parsed floating point
numbers from their text representation. If an application using Ruby
accepted untrusted input strings and converted them to floating point
numbers, an attacker able to provide such input could cause the
application to crash or, possibly, execute arbitrary code with the
privileges of the application. (CVE-2013-4164)

All ruby users are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001124.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?682eda75"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ruby-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-devel-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-docs-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-irb-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-libs-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-rdoc-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-ri-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-static-1.8.7.352-13.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-tcltk-1.8.7.352-13.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
