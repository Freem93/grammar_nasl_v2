#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0581 and 
# CentOS Errata and Security Advisory 2013:0581 respectively.
#

include("compat.inc");

if (description)
{
  script_id(64971);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2013-0338");
  script_bugtraq_id(58180);
  script_osvdb_id(90631);
  script_xref(name:"RHSA", value:"2013:0581");

  script_name(english:"CentOS 5 / 6 : libxml2 (CESA-2013:0581)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libxml2 packages that fix one security issue are now available
for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

The libxml2 library is a development toolbox providing the
implementation of various XML standards.

A denial of service flaw was found in the way libxml2 performed string
substitutions when entity values for entity references replacement was
enabled. A remote attacker could provide a specially crafted XML file
that, when processed by an application linked against libxml2, would
lead to excessive CPU consumption. (CVE-2013-0338)

All users of libxml2 are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. The desktop
must be restarted (log out, then log back in) for this update to take
effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019260.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e78b68e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019627.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?586ef148"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-March/000813.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0bf52470"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxml2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"libxml2-2.6.26-2.1.21.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-devel-2.6.26-2.1.21.el5_9.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libxml2-python-2.6.26-2.1.21.el5_9.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"libxml2-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-devel-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-python-2.7.6-12.el6_4.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libxml2-static-2.7.6-12.el6_4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
