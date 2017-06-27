#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0140 and 
# CentOS Errata and Security Advisory 2012:0140 respectively.
#

include("compat.inc");

if (description)
{
  script_id(58041);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:09:24 $");

  script_cve_id("CVE-2011-3026");
  script_osvdb_id(79294);
  script_xref(name:"RHSA", value:"2012:0140");

  script_name(english:"CentOS 6 : thunderbird (CESA-2012:0140)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes one security issue is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A heap-based buffer overflow flaw was found in the way Thunderbird
handled PNG (Portable Network Graphics) images. An HTML mail message
or remote content containing a specially crafted PNG image could cause
Thunderbird to crash or, possibly, execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2011-3026)

All Thunderbird users should upgrade to this updated package, which
corrects this issue. After installing the update, Thunderbird must be
restarted for the changes to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-February/018444.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6add6a61"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"thunderbird-3.1.18-2.el6.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
