#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0117 and 
# CentOS Errata and Security Advisory 2006:0117 respectively.
#

include("compat.inc");

if (description)
{
  script_id(21880);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:25:25 $");

  script_cve_id("CVE-2005-1038");
  script_bugtraq_id(13024);
  script_xref(name:"RHSA", value:"2006:0117");

  script_name(english:"CentOS 3 : vixie-cron (CESA-2006:0117)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vixie-cron package that fixes a bug and security issue is
now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The vixie-cron package contains the Vixie version of cron. Cron is a
standard UNIX daemon that runs specified programs at scheduled times.

A bug was found in the way vixie-cron installs new crontab files. It
is possible for a local attacker to execute the crontab command in
such a way that they can view the contents of another user's crontab
file. The Common Vulnerabilities and Exposures project assigned the
name CVE-2005-1038 to this issue.

This update also fixes an issue where cron jobs could start before
their scheduled time.

All users of vixie-cron should upgrade to this updated package, which
contains backported patches and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012744.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1ef37f0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012745.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00e749f2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-March/012761.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef1c1f9f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vixie-cron package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:vixie-cron");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/03/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
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
if (rpm_check(release:"CentOS-3", reference:"vixie-cron-4.1-10.EL3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
