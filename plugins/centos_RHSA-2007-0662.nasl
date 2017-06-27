#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0662 and 
# CentOS Errata and Security Advisory 2007:0662 respectively.
#

include("compat.inc");

if (description)
{
  script_id(25713);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/30 15:10:02 $");

  script_cve_id("CVE-2007-3304");
  script_bugtraq_id(24215);
  script_osvdb_id(37050, 38939);
  script_xref(name:"RHSA", value:"2007:0662");

  script_name(english:"CentOS 3 / 4 : httpd (CESA-2007:0662)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated Apache httpd packages that correct a security issue are now
available for Red Hat Enterprise Linux 3 and 4.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The Apache HTTP Server is a popular Web server.

The Apache HTTP Server did not verify that a process was an Apache
child process before sending it signals. A local attacker with the
ability to run scripts on the Apache HTTP Server could manipulate the
scoreboard and cause arbitrary processes to be terminated which could
lead to a denial of service. (CVE-2007-3304).

Users of httpd should upgrade to these updated packages, which contain
backported patches to correct this issue. Users should restart Apache
after installing this update."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014033.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37e8c5c7"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014034.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9fd16fd3"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014036.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c49ee98"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?83edfa50"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18a48088"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-July/014044.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08a5e1b0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected httpd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:httpd-suexec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"httpd-2.0.46-68.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"httpd-devel-2.0.46-68.ent.centos")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mod_ssl-2.0.46-68.ent.centos")) flag++;

if (rpm_check(release:"CentOS-4", reference:"httpd-2.0.52-32.3.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-devel-2.0.52-32.3.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-manual-2.0.52-32.3.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"httpd-suexec-2.0.52-32.3.ent.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mod_ssl-2.0.52-32.3.ent.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
