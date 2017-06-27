#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0594 and 
# CentOS Errata and Security Advisory 2016:0594 respectively.
#

include("compat.inc");

if (description)
{
  script_id(90368);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1526");
  script_osvdb_id(134244, 134245, 134246);
  script_xref(name:"RHSA", value:"2016:0594");

  script_name(english:"CentOS 7 : graphite2 (CESA-2016:0594)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for graphite2 is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

Graphite2 is a project within SIL's Non-Roman Script Initiative and
Language Software Development groups to provide rendering capabilities
for complex non-Roman writing systems. Graphite can be used to create
'smart fonts' capable of displaying writing systems with various
complex behaviors. With respect to the Text Encoding Model, Graphite
handles the 'Rendering' aspect of writing system implementation.

The following packages have been upgraded to a newer upstream version:
graphite2 (1.3.6).

Security Fix(es) :

* Various vulnerabilities have been discovered in Graphite2. An
attacker able to trick an unsuspecting user into opening specially
crafted font files in an application using Graphite2 could exploit
these flaws to cause the application to crash or, potentially, execute
arbitrary code with the privileges of the application. (CVE-2016-1521,
CVE-2016-1522, CVE-2016-1523, CVE-2016-1526)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-April/021811.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cda9c955"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected graphite2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:graphite2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:graphite2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"graphite2-1.3.6-1.el7_2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"graphite2-devel-1.3.6-1.el7_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
