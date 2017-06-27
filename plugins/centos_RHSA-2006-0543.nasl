#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0543 and 
# CentOS Errata and Security Advisory 2006:0543 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21999);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2006-2447");
  script_osvdb_id(26177);
  script_xref(name:"RHSA", value:"2006:0543");

  script_name(english:"CentOS 4 : spamassassin (CESA-2006:0543)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated spamassassin packages that fix an arbitrary code execution
flaw are now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

SpamAssassin provides a way to reduce unsolicited commercial email
(SPAM) from incoming email.

A flaw was found with the way the Spamassassin spamd daemon processes
the virtual pop username passed to it. If a site is running spamd with
both the --vpopmail and --paranoid flags, it is possible for a remote
user with the ability to connect to the spamd daemon to execute
arbitrary commands as the user running the spamd daemon.
(CVE-2006-2447)

Note: None of the IMAP or POP servers shipped with Red Hat Enterprise
Linux 4 support vpopmail delivery. Running spamd with the --vpopmail
and --paranoid flags is uncommon and not the default startup option as
shipped with Red Hat Enterprise Linux 4.

Spamassassin, as shipped in Red Hat Enterprise Linux 4, performs RBL
lookups against visi.com to help determine if an email is spam.
However, this DNS RBL has recently disappeared, resulting in mail
filtering delays and timeouts.

Users of SpamAssassin should upgrade to these updated packages
containing version 3.0.6 and backported patches, which are not
vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012944.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e8749c2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012947.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24833713"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-June/012948.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0abd4db0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected spamassassin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SpamAssassin spamd Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:spamassassin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/06");
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
if (rpm_check(release:"CentOS-4", reference:"spamassassin-3.0.6-1.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
