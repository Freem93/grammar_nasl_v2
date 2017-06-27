#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0074 and 
# CentOS Errata and Security Advisory 2007:0074 respectively.
#

include("compat.inc");

if (description)
{
  script_id(24702);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/03/19 14:21:01 $");

  script_cve_id("CVE-2007-0451");
  script_bugtraq_id(22584);
  script_osvdb_id(33207);
  script_xref(name:"RHSA", value:"2007:0074");

  script_name(english:"CentOS 4 : spamassassin (CESA-2007:0074)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spamassassin packages that fix a security issue are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

SpamAssassin provides a way to reduce unsolicited commercial email
(spam) from incoming email.

A flaw was found in the way SpamAssassin processes HTML email
containing URIs. A carefully crafted mail message could cause
SpamAssassin to consume significant resources. If a number of these
messages are sent, this could lead to a denial of service, potentially
delaying or preventing the delivery of email. (CVE-2007-0451)

Users of SpamAssassin should upgrade to these updated packages which
contain version 3.1.8 which is not vulnerable to these issues.

This is an upgrade from SpamAssassin version 3.0.6 to 3.1.8, which
contains many bug fixes and spam detection enhancements. Further
details are available in the SpamAssassin 3.1 changelog and upgrade
guide."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013560.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?75cd4722"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013562.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?315673f2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-February/013563.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bd1642e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"spamassassin-3.1.8-2.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
