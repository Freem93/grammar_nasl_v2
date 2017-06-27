#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2011:0153 and 
# CentOS Errata and Security Advisory 2011:0153 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51785);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/05/19 23:43:08 $");

  script_cve_id("CVE-2010-4345");
  script_bugtraq_id(45341);
  script_xref(name:"RHSA", value:"2011:0153");

  script_name(english:"CentOS 4 / 5 : exim (CESA-2011:0153)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated exim packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on UNIX systems connected to the Internet.

A privilege escalation flaw was discovered in Exim. If an attacker
were able to gain access to the 'exim' user, they could cause Exim to
execute arbitrary commands as the root user. (CVE-2010-4345)

This update adds a new configuration file,
'/etc/exim/trusted-configs'. To prevent Exim from running arbitrary
commands as root, Exim will now drop privileges when run with a
configuration file not listed as trusted. This could break backwards
compatibility with some Exim configurations, as the trusted-configs
file only trusts '/etc/exim/exim.conf' and '/etc/exim/exim4.conf' by
default. If you are using a configuration file not listed in the new
trusted-configs file, you will need to add it manually.

Additionally, Exim will no longer allow a user to execute exim as root
with the -D command line option to override macro definitions. All
macro definitions that require root permissions must now reside in a
trusted configuration file.

Users of Exim are advised to upgrade to these updated packages, which
contain a backported patch to correct this issue. After installing
this update, the exim daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017338.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?65967174"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-April/017339.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a1a9fefc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32d8fc42"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017244.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?31810388"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.3")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.3")) flag++;

if (rpm_check(release:"CentOS-5", reference:"exim-4.63-5.el5_6.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"exim-mon-4.63-5.el5_6.2")) flag++;
if (rpm_check(release:"CentOS-5", reference:"exim-sa-4.63-5.el5_6.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
