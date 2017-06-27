#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0579 and 
# CentOS Errata and Security Advisory 2008:0579 respectively.
#

include("compat.inc");

if (description)
{
  script_id(33736);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:34:19 $");

  script_cve_id("CVE-2008-2375");
  script_osvdb_id(46930);
  script_xref(name:"RHSA", value:"2008:0579");

  script_name(english:"CentOS 3 : vsftpd (CESA-2008:0579)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vsftpd package that fixes a security issue is now
available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

vsftpd (Very Secure File Transfer Protocol (FTP) daemon) is a secure
FTP server for Linux and Unix-like systems.

The version of vsftpd as shipped in Red Hat Enterprise Linux 3 when
used in combination with Pluggable Authentication Modules (PAM) had a
memory leak on an invalid authentication attempt. Since vsftpd prior
to version 2.0.5 allows any number of invalid attempts on the same
connection this memory leak could lead to an eventual DoS.
(CVE-2008-2375)

This update mitigates this security issue by including a backported
patch which terminates a session after a given number of failed log in
attempts. The default number of attempts is 3 and this can be
configured using the 'max_login_fails' directive.

All vsftpd users should upgrade to this updated package, which
addresses this vulnerability."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1fabf0fc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015166.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d87e1d5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-July/015167.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54a5b8b9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vsftpd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vsftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"vsftpd-1.2.1-3E.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
