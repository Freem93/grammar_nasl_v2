#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0321 and 
# CentOS Errata and Security Advisory 2012:0321 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58108);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:00 $");

  script_cve_id("CVE-2012-0804");
  script_bugtraq_id(51943);
  script_osvdb_id(78987);
  script_xref(name:"RHSA", value:"2012:0321");

  script_name(english:"CentOS 5 / 6 : cvs (CESA-2012:0321)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated cvs packages that fix one security issue are now available for
Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Concurrent Version System (CVS) is a version control system that can
record the history of your files.

A heap-based buffer overflow flaw was found in the way the CVS client
handled responses from HTTP proxies. A malicious HTTP proxy could use
this flaw to cause the CVS client to crash or, possibly, execute
arbitrary code with the privileges of the user running the CVS client.
(CVE-2012-0804)

All users of cvs are advised to upgrade to these updated packages,
which contain a patch to correct this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018453.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfad6165"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-January/000326.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4edf0b2b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected cvs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cvs-inetd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"cvs-1.11.22-11.el5_8.1")) flag++;
if (rpm_check(release:"CentOS-5", reference:"cvs-inetd-1.11.22-11.el5_8.1")) flag++;

if (rpm_check(release:"CentOS-6", reference:"cvs-1.11.23-11.el6_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
