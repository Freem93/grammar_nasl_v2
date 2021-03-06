#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0197 and 
# CentOS Errata and Security Advisory 2016:0197 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88762);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2016-1521", "CVE-2016-1522", "CVE-2016-1523", "CVE-2016-1969");
  script_osvdb_id(134244, 134245, 134246);
  script_xref(name:"RHSA", value:"2016:0197");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2016:0197)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

Multiple security flaws were found in the graphite2 font library
shipped with Firefox. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2016-1521,
CVE-2016-1522, CVE-2016-1523)

All Firefox users should upgrade to these updated packages, which
contain Firefox version 38.6.1 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021667.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?025bd82b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021669.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0e94b022"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-February/021671.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?920f882b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:U/RC:U");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-38.6.1-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-38.6.1-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-38.6.1-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
