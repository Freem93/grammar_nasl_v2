#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:498 and 
# CentOS Errata and Security Advisory 2005:498 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21940);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2005-1266");
  script_osvdb_id(17346);
  script_xref(name:"RHSA", value:"2005:498");

  script_name(english:"CentOS 4 : spamassassin (CESA-2005:498)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated spamassassin package that fixes a denial of service bug
when parsing malformed messages is now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SpamAssassin provides a way to reduce unsolicited commercial email
(SPAM) from incoming email.

A denial of service bug has been found in SpamAssassin. An attacker
could construct a message in such a way that would cause SpamAssassin
to consume CPU resources. If a number of these messages were sent it
could lead to a denial of service, potentially preventing the delivery
or filtering of email. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2005-1266 to this
issue.

SpamAssassin version 3.0.4 additionally solves a number of bugs
including: - #156390 Spamassassin consumes too much memory during
learning - #155423 URI blacklist spam bypass - #147464 Users may now
disable subject rewriting - Smarter default Bayes scores - Numerous
other bug fixes that improve spam filter accuracy and safety

For full details, please refer to the change details of 3.0.2, 3.0.3,
and 3.0.4 in SpamAssassin's online documentation at the following
address: http://wiki.apache.org/spamassassin/NextRelease

Users of SpamAssassin should update to this updated package,
containing version 3.0.4 which is not vulnerable to this issue and
resolves these bugs."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6d4d8f9"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1b640ca"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-June/011898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7a960e4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"spamassassin-3.0.4-1.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
