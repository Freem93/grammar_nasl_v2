#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0600 and 
# CentOS Errata and Security Advisory 2006:0600 respectively.
#

include("compat.inc");

if (description)
{
  script_id(22320);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:25:26 $");

  script_cve_id("CVE-2006-2941", "CVE-2006-3636");
  script_bugtraq_id(19831);
  script_osvdb_id(28437, 28438);
  script_xref(name:"RHSA", value:"2006:0600");

  script_name(english:"CentOS 3 / 4 : mailman (CESA-2006:0600)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mailman packages that fix security issues are now available
for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mailman is a program used to help manage email discussion lists.

A flaw was found in the way Mailman handled MIME multipart messages.
An attacker could send a carefully crafted MIME multipart email
message to a mailing list run by Mailman which caused that particular
mailing list to stop working. (CVE-2006-2941)

Several cross-site scripting (XSS) issues were found in Mailman. An
attacker could exploit these issues to perform cross-site scripting
attacks against the Mailman administrator. (CVE-2006-3636)

Red Hat would like to thank Barry Warsaw for disclosing these
vulnerabilities.

Users of Mailman should upgrade to these updated packages, which
contain backported patches to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013201.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17fccb73"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013202.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31feee01"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013205.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c4a0caa"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013207.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f8e3605b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013213.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e5e02809"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013214.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5fe24def"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mailman package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mailman");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/12");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/02");
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
if (rpm_check(release:"CentOS-3", reference:"mailman-2.1.5.1-25.rhel3.7")) flag++;

if (rpm_check(release:"CentOS-4", reference:"mailman-2.1.5.1-34.rhel4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
