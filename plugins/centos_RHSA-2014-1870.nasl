#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1870 and 
# CentOS Errata and Security Advisory 2014:1870 respectively.
#

include("compat.inc");

if (description)
{
  script_id(79313);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/04 14:39:53 $");

  script_cve_id("CVE-2014-0209", "CVE-2014-0210", "CVE-2014-0211");
  script_bugtraq_id(67382);
  script_osvdb_id(106970, 106971, 106972, 106973, 106974, 106975, 106976, 106977, 106978, 106979, 106980, 106981);
  script_xref(name:"RHSA", value:"2014:1870");

  script_name(english:"CentOS 6 / 7 : libXfont (CESA-2014:1870)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libXfont packages that fix three security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The libXfont packages provide the X.Org libXfont runtime library.
X.Org is an open source implementation of the X Window System.

A use-after-free flaw was found in the way libXfont processed certain
font files when attempting to add a new directory to the font path. A
malicious, local user could exploit this issue to potentially execute
arbitrary code with the privileges of the X.Org server.
(CVE-2014-0209)

Multiple out-of-bounds write flaws were found in the way libXfont
parsed replies received from an X.org font server. A malicious X.org
server could cause an X client to crash or, possibly, execute
arbitrary code with the privileges of the X.Org server.
(CVE-2014-0210, CVE-2014-0211)

Red Hat would like to thank the X.org project for reporting these
issues. Upstream acknowledges Ilja van Sprundel as the original
reporter.

Users of libXfont should upgrade to these updated packages, which
contain a backported patch to resolve this issue. All running X.Org
server instances must be restarted for the update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d154d1e4"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-November/020769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92e7f65c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libxfont packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libXfont-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/19");
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
if (rpm_check(release:"CentOS-6", reference:"libXfont-1.4.5-4.el6_6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libXfont-devel-1.4.5-4.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-1.4.7-2.el7_0")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libXfont-devel-1.4.7-2.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
