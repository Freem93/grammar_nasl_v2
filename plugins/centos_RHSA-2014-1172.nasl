#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1172 and 
# CentOS Errata and Security Advisory 2014:1172 respectively.
#

include("compat.inc");

if (description)
{
  script_id(77609);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/20 13:54:06 $");

  script_cve_id("CVE-2014-3618");
  script_bugtraq_id(69573);
  script_osvdb_id(110889);
  script_xref(name:"RHSA", value:"2014:1172");

  script_name(english:"CentOS 5 / 6 / 7 : procmail (CESA-2014:1172)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated procmail packages that fix one security issue are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The procmail program is used for local mail delivery. In addition to
just delivering mail, procmail can be used for automatic filtering,
presorting, and other mail handling jobs.

A heap-based buffer overflow flaw was found in procmail's formail
utility. A remote attacker could send an email with specially crafted
headers that, when processed by formail, could cause procmail to crash
or, possibly, execute arbitrary code as the user running formail.
(CVE-2014-3618)

All procmail users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020550.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9f81d7e0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020551.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?860c0276"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-September/020552.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3128096a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected procmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:procmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-5", reference:"procmail-3.22-17.1.2.el5_10")) flag++;

if (rpm_check(release:"CentOS-6", reference:"procmail-3.22-25.1.el6_5.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"procmail-3.22-34.el7_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
