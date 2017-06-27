#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1090 and 
# CentOS Errata and Security Advisory 2013:1090 respectively.
#

include("compat.inc");

if (description)
{
  script_id(68941);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-4073");
  script_bugtraq_id(60843);
  script_osvdb_id(94628);
  script_xref(name:"RHSA", value:"2013:1090");

  script_name(english:"CentOS 5 / 6 : ruby (CESA-2013:1090)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

A flaw was found in Ruby's SSL client's hostname identity check when
handling certificates that contain hostnames with NULL bytes. An
attacker could potentially exploit this flaw to conduct
man-in-the-middle attacks to spoof SSL servers. Note that to exploit
this issue, an attacker would need to obtain a carefully-crafted
certificate signed by an authority that the client trusts.
(CVE-2013-4073)

All users of Ruby are advised to upgrade to these updated packages,
which contain backported patches to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-July/019861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b241a6a9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-July/019862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30e61be8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-31.el5_9")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-31.el5_9")) flag++;

if (rpm_check(release:"CentOS-6", reference:"ruby-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-devel-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-docs-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-irb-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-libs-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-rdoc-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-ri-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-static-1.8.7.352-12.el6_4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ruby-tcltk-1.8.7.352-12.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
