#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0252 and 
# CentOS Errata and Security Advisory 2007:0252 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67046);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2006-7176");
  script_xref(name:"RHSA", value:"2007:0252");

  script_name(english:"CentOS 4 : sendmail (CESA-2007:0252)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated sendmail packages that fix a security issue and various bugs
are now available for Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Sendmail is a very widely used Mail Transport Agent (MTA). MTAs
deliver mail from one machine to another. Sendmail is not a client
program, but rather a behind-the-scenes daemon that moves email over
networks or the Internet to its final destination.

The configuration of Sendmail on Red Hat Enterprise Linux was found to
not reject the 'localhost.localdomain' domain name for e-mail messages
that came from external hosts. This could have allowed remote
attackers to disguise spoofed messages (CVE-2006-7176).

This updated package also fixes the following bugs :

* Infinite loop within tls read.

* Incorrect path to selinuxenabled in initscript.

* Build artifacts from sendmail-cf package.

* Missing socketmap support.

* Add support for CipherList configuration directive.

* Path for aliases file.

* Failure of shutting down sm-client.

* Allows to specify persistent queue runners.

* Missing dnl for SMART_HOST define.

* Fixes connections stay in CLOSE_WAIT.

All users of Sendmail should upgrade to these updated packages, which
contains backported patches to resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013706.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected sendmail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-cf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sendmail-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sendmail-8.13.1-3.2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sendmail-cf-8.13.1-3.2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sendmail-devel-8.13.1-3.2.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"sendmail-doc-8.13.1-3.2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
