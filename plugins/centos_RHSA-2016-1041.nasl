#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1041 and 
# CentOS Errata and Security Advisory 2016:1041 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91106);
  script_version("$Revision: 2.12 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-2805", "CVE-2016-2807");
  script_osvdb_id(135562, 137609, 137613, 137614, 137615, 137616);
  script_xref(name:"RHSA", value:"2016:1041");

  script_name(english:"CentOS 5 / 6 / 7 : thunderbird (CESA-2016:1041)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for thunderbird is now available for Red Hat Enterprise
Linux 5, Red Hat Enterprise Linux 6, and Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 38.8.0.

Security Fix(es) :

* Two flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Thunderbird to crash
or, potentially, execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2016-2805, CVE-2016-2807)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Phil Ringalda, Christian Holler, and
Tyson Smith as the original reporters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021890.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021892.html"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-May/003103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b78c4dd0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"thunderbird-38.8.0-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"thunderbird-38.8.0-2.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"thunderbird-38.8.0-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
