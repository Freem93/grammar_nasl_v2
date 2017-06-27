#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0890 and 
# CentOS Errata and Security Advisory 2007:0890 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(26075);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-2756", "CVE-2007-2872", "CVE-2007-3799", "CVE-2007-3996", "CVE-2007-3998", "CVE-2007-4658", "CVE-2007-4670");
  script_bugtraq_id(24089, 24261, 24268, 25498);
  script_osvdb_id(36083, 36855, 36858, 36863, 36865, 36870);
  script_xref(name:"RHSA", value:"2007:0890");

  script_name(english:"CentOS 4 / 5 : php (CESA-2007:0890)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated PHP packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

PHP is an HTML-embedded scripting language commonly used with the
Apache HTTP Web server.

Various integer overflow flaws were found in the PHP gd extension. A
script that could be forced to resize images from an untrusted source
could possibly allow a remote attacker to execute arbitrary code as
the apache user. (CVE-2007-3996)

An integer overflow flaw was found in the PHP chunk_split function. If
a remote attacker was able to pass arbitrary data to the third
argument of chunk_split they could possibly execute arbitrary code as
the apache user. Note that it is unusual for a PHP script to use the
chunk_script function with a user-supplied third argument.
(CVE-2007-2872)

A previous security update introduced a bug into PHP session cookie
handling. This could allow an attacker to stop a victim from viewing a
vulnerable website if the victim has first visited a malicious web
page under the control of the attacker, and that page can set a cookie
for the vulnerable website. (CVE-2007-4670)

A flaw was found in the PHP money_format function. If a remote
attacker was able to pass arbitrary data to the money_format function
this could possibly result in an information leak or denial of
service. Note that is is unusual for a PHP script to pass
user-supplied data to the money_format function. (CVE-2007-4658)

A flaw was found in the PHP wordwrap function. If a remote attacker
was able to pass arbitrary data to the wordwrap function this could
possibly result in a denial of service. (CVE-2007-3998)

A bug was found in PHP session cookie handling. This could allow an
attacker to create a cross-site cookie insertion attack if a victim
follows an untrusted carefully-crafted URL. (CVE-2007-3799)

An infinite-loop flaw was discovered in the PHP gd extension. A script
that could be forced to process PNG images from an untrusted source
could allow a remote attacker to cause a denial of service.
(CVE-2007-2756)

Users of PHP should upgrade to these updated packages, which contain
backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014215.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4f59f016"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014223.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5636c9e9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014224.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b91a7504"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014229.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b30b9caa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-September/014230.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?95e6bbbb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-dba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-domxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-ncurses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pear");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/09/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/24");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"php-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-devel-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-domxml-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-gd-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-imap-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ldap-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mbstring-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-mysql-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-ncurses-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-odbc-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pear-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-pgsql-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-snmp-4.3.9-3.22.9")) flag++;
if (rpm_check(release:"CentOS-4", reference:"php-xmlrpc-4.3.9-3.22.9")) flag++;

if (rpm_check(release:"CentOS-5", reference:"php-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-bcmath-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-cli-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-common-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-dba-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-devel-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-gd-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-imap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ldap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mbstring-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-mysql-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-ncurses-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-odbc-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pdo-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-pgsql-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-snmp-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-soap-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xml-5.1.6-15.el5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"php-xmlrpc-5.1.6-15.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
