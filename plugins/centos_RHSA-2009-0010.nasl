#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:0010 and 
# CentOS Errata and Security Advisory 2009:0010 respectively.
#

include("compat.inc");

if (description)
{
  script_id(35353);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-2379", "CVE-2008-3663");
  script_bugtraq_id(31321);
  script_xref(name:"RHSA", value:"2009:0010");

  script_name(english:"CentOS 3 / 4 / 5 : squirrelmail (CESA-2009:0010)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that resolves various security issues
is now available for Red Hat Enterprise Linux 3, 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SquirrelMail is an easy-to-configure, standards-based, webmail package
written in PHP. It includes built-in PHP support for the IMAP and SMTP
protocols, and pure HTML 4.0 page-rendering (with no JavaScript
required) for maximum browser-compatibility, strong MIME support,
address books, and folder manipulation.

Ivan Markovic discovered a cross-site scripting (XSS) flaw in
SquirrelMail caused by insufficient HTML mail sanitization. A remote
attacker could send a specially crafted HTML mail or attachment that
could cause a user's Web browser to execute a malicious script in the
context of the SquirrelMail session when that email or attachment was
opened by the user. (CVE-2008-2379)

It was discovered that SquirrelMail allowed cookies over insecure
connections (ie did not restrict cookies to HTTPS connections). An
attacker who controlled the communication channel between a user and
the SquirrelMail server, or who was able to sniff the user's network
communication, could use this flaw to obtain the user's session
cookie, if a user made an HTTP request to the server. (CVE-2008-3663)

Note: After applying this update, all session cookies set for
SquirrelMail sessions started over HTTPS connections will have the
'secure' flag set. That is, browsers will only send such cookies over
an HTTPS connection. If needed, you can revert to the previous
behavior by setting the configuration option '$only_secure_cookies' to
'false' in SquirrelMail's /etc/squirrelmail/config.php configuration
file.

Users of squirrelmail should upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015597.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7918d825"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-February/015599.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed0fb00b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015540.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?798e7984"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015541.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c1c66ac"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015546.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e67022a8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015547.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67c37c10"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015554.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d562bff2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-January/015555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?94f3e197"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"squirrelmail-1.4.8-8.el3.centos.1")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"ia64", reference:"squirrelmail-1.4.8-9.el3")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"squirrelmail-1.4.8-8.el3.centos.1")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"squirrelmail-1.4.8-5.el4.centos.2")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"squirrelmail-1.4.8-5.c4.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"squirrelmail-1.4.8-5.el4.centos.2")) flag++;

if (rpm_check(release:"CentOS-5", reference:"squirrelmail-1.4.8-5.el5.centos.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
