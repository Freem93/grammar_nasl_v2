#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0970 and 
# CentOS Errata and Security Advisory 2010:0970 respectively.
#

include("compat.inc");

if (description)
{
  script_id(51780);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/03/12 15:37:15 $");

  script_cve_id("CVE-2010-4344");
  script_bugtraq_id(45308);
  script_osvdb_id(69685);
  script_xref(name:"RHSA", value:"2010:0970");

  script_name(english:"CentOS 4 : exim (CESA-2010:0970)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated exim packages that fix one security issue are now available
for Red Hat Enterprise Linux 4 and 5, and Red Hat Enterprise Linux
4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Exim is a mail transport agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet.

A buffer overflow flaw was discovered in Exim's internal
string_vformat() function. A remote attacker could use this flaw to
execute arbitrary code on the mail server running Exim.
(CVE-2010-4344)

Note: successful exploitation would allow a remote attacker to execute
arbitrary code as root on a Red Hat Enterprise Linux 4 or 5 system
that is running the Exim mail server. An exploit for this issue is
known to exist.

For additional information regarding this flaw, along with mitigation
advice, please see the Knowledge Base article linked to in the
References section of this advisory.

Users of Exim are advised to update to these erratum packages which
contain a backported patch to correct this issue. After installing
this update, the Exim daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017233.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ff04b3d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2011-January/017234.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7491ea5b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected exim packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim4 string_format Function Heap Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:exim-sa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-doc-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-mon-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"exim-sa-4.43-1.RHEL4.5.el4_8.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
