#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0779 and 
# CentOS Errata and Security Advisory 2007:0779 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67057);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2006-4624");
  script_osvdb_id(28436);
  script_xref(name:"RHSA", value:"2007:0779");

  script_name(english:"CentOS 4 : mailman (CESA-2007:0779)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mailman packages that fix a security issue and various bugs
are now available for Red Hat Enterprise Linux 4.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Mailman is a program used to help manage email discussion lists.

A flaw was found in Mailman. A remote attacker could spoof messages in
the error log, and possibly trick the administrator into visiting
malicious URLs via a carriage return/line feed sequence in the URI.
(CVE-2006-4624)

As well, these updated packages fix the following bugs :

* canceling a subscription on the confirm subscription request page
caused mailman to crash.

* editing the sender filter caused all spam filter rules to be
deleted.

* the migrate-fhs script was not included.

* the mailman init script returned a zero (success) exit code even
when an incorrect command was given. For example, the 'mailman foo'
command returned a zero exit code. In these updated packages the
mailmain init script returns the correct exit codes.

Users of Mailman are advised to upgrade to these updated packages,
which resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014423.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0ef7fc75"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/02");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"mailman-2.1.5.1-34.rhel4.6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
