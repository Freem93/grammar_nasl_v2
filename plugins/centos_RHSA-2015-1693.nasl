#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:1693 and 
# CentOS Errata and Security Advisory 2015:1693 respectively.
#

include("compat.inc");

if (description)
{
  script_id(86498);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/10/22 14:23:03 $");

  script_cve_id("CVE-2015-4497", "CVE-2015-4498");
  script_osvdb_id(126767, 126768);
  script_xref(name:"RHSA", value:"2015:1693");

  script_name(english:"CentOS 5 / 6 / 7 : firefox (CESA-2015:1693)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix two security issues are now
available for Red Hat Enterprise Linux 5, 6, and 7.

Red Hat Product Security has rated this update as having Critical
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

Mozilla Firefox is an open source web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox.

A flaw was found in the processing of malformed web content. A web
page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2015-4497)

A flaw was found in the way Firefox handled installation of add-ons.
An attacker could use this flaw to bypass the add-on installation
prompt, and trick the user inso installing an add-on from a malicious
source. (CVE-2015-4498)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Jean-Max Reymond, Ucha Gobejishvili, and
Bas Venis as the original reporters of these issues.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 38.2.1 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021351.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?adc5d4e5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021352.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?acd25e3a"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-August/021353.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?69015789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"firefox-38.2.1-1.el5.centos")) flag++;

if (rpm_check(release:"CentOS-6", reference:"firefox-38.2.1-1.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"firefox-38.2.1-1.el7.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
