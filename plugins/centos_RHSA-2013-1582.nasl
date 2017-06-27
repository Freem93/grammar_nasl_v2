#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:1582 and 
# CentOS Errata and Security Advisory 2013:1582 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79163);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/12/15 05:42:13 $");

  script_cve_id("CVE-2013-4238");
  script_bugtraq_id(61738);
  script_osvdb_id(96215);
  script_xref(name:"RHSA", value:"2013:1582");

  script_name(english:"CentOS 6 : python (CESA-2013:1582)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated python packages that fix one security issue, several bugs, and
add one enhancement are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Python is an interpreted, interactive, object-oriented programming
language.

A flaw was found in the way the Python SSL module handled X.509
certificate fields that contain a NULL byte. An attacker could
potentially exploit this flaw to conduct man-in-the-middle attacks to
spoof SSL servers. Note that to exploit this issue, an attacker would
need to obtain a carefully crafted certificate signed by an authority
that the client trusts. (CVE-2013-4238)

These updated python packages include numerous bug fixes and one
enhancement. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.5
Technical Notes, linked to in the References, for information on the
most significant of these changes.

All users of python are advised to upgrade to these updated packages,
which fix these issues and add this enhancement."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-November/001056.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b2c4ad6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tkinter");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"python-2.6.6-51.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-devel-2.6.6-51.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-libs-2.6.6-51.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-test-2.6.6-51.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"python-tools-2.6.6-51.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"tkinter-2.6.6-51.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
