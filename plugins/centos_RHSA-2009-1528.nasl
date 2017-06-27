#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1528 and 
# CentOS Errata and Security Advisory 2009:1528 respectively.
#

include("compat.inc");

if (description)
{
  script_id(42265);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/04 14:30:42 $");

  script_cve_id("CVE-2009-2906");
  script_bugtraq_id(36573);
  script_xref(name:"RHSA", value:"2009:1528");

  script_name(english:"CentOS 3 : samba (CESA-2009:1528)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba packages that fix a security issue and a bug are now
available for Red Hat Enterprise Linux 3.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Samba is a suite of programs used by machines to share files,
printers, and other information.

A denial of service flaw was found in the Samba smbd daemon. An
authenticated, remote user could send a specially crafted response
that would cause an smbd child process to enter an infinite loop. An
authenticated, remote user could use this flaw to exhaust system
resources by opening multiple CIFS sessions. (CVE-2009-2906)

This update also fixes the following bug :

* the RHSA-2007:0354 update added code to escape input passed to
scripts that are run by Samba. This code was missing 'c' from the list
of valid characters, causing it to be escaped. With this update, the
previous patch has been updated to include 'c' in the list of valid
characters. (BZ#242754)

Users of Samba should upgrade to these updated packages, which contain
a backported patch to correct this issue. After installing this
update, the smb service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016198.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1823396c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-October/016199.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2fecc499"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/28");
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
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-client-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-client-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-common-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-common-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-swat-3.0.9-1.3E.16")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-swat-3.0.9-1.3E.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
