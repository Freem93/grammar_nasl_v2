#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0129 and 
# CentOS Errata and Security Advisory 2013:0129 respectively.
#

include("compat.inc");

if (description)
{
  script_id(63574);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2012-4481", "CVE-2012-4522");
  script_bugtraq_id(55813, 56115);
  script_osvdb_id(70957, 87917);
  script_xref(name:"RHSA", value:"2013:0129");

  script_name(english:"CentOS 5 : ruby (CESA-2013:0129)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix two security issues and one bug are now
available for Red Hat Enterprise Linux 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Ruby is an extensible, interpreted, object-oriented, scripting
language. It has features to process text files and to do system
management tasks.

It was found that certain methods did not sanitize file names before
passing them to lower layer routines in Ruby. If a Ruby application
created files with names based on untrusted input, it could result in
the creation of files with different names than expected.
(CVE-2012-4522)

It was found that the RHSA-2011:0909 update did not correctly fix the
CVE-2011-1005 issue, a flaw in the method for translating an exception
message into a string in the Exception class. A remote attacker could
use this flaw to bypass safe level 4 restrictions, allowing untrusted
(tainted) code to modify arbitrary, trusted (untainted) strings, which
safe level 4 restrictions would otherwise prevent. (CVE-2012-4481)

The CVE-2012-4481 issue was discovered by Vit Ondruch of Red Hat.

This update also fixes the following bug :

* Prior to this update, the 'rb_syck_mktime' option could, under
certain circumstances, terminate with a segmentation fault when
installing libraries with certain gems. This update modifies the
underlying code so that Ruby gems can be installed as expected.
(BZ#834381)

All users of Ruby are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-January/019162.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1a15067"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000429.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d8b6cc16"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"ruby-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-devel-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-docs-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-irb-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-libs-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-mode-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-rdoc-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-ri-1.8.5-27.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"ruby-tcltk-1.8.5-27.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
