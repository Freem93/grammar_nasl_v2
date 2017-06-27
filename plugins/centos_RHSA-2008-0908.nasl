#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2008:0908 and 
# CentOS Errata and Security Advisory 2008:0908 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(34339);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/11/17 20:59:09 $");

  script_cve_id("CVE-2008-0016", "CVE-2008-3835", "CVE-2008-4058", "CVE-2008-4059", "CVE-2008-4060", "CVE-2008-4061", "CVE-2008-4062", "CVE-2008-4065", "CVE-2008-4066", "CVE-2008-4067", "CVE-2008-4068", "CVE-2008-4070");
  script_osvdb_id(48746, 48747, 48748, 48749, 48750, 48751, 48759, 48760, 48761, 48769, 48770, 48771, 48772, 48773, 48780);
  script_xref(name:"RHSA", value:"2008:0908");

  script_name(english:"CentOS 4 / 5 : thunderbird (CESA-2008:0908)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed HTML mail
content. An HTML mail message containing malicious content could cause
Thunderbird to crash or, potentially, execute arbitrary code as the
user running Thunderbird. (CVE-2008-0016, CVE-2008-4058,
CVE-2008-4059, CVE-2008-4060, CVE-2008-4061, CVE-2008-4062)

Several flaws were found in the way malformed HTML mail content was
displayed. An HTML mail message containing specially crafted content
could potentially trick a Thunderbird user into surrendering sensitive
information. (CVE-2008-3835, CVE-2008-4067, CVE-2008-4068)

A flaw was found in Thunderbird that caused certain characters to be
stripped from JavaScript code. This flaw could allow malicious
JavaScript to bypass or evade script filters. (CVE-2008-4065,
CVE-2008-4066)

Note: JavaScript support is disabled by default in Thunderbird; the
above issue is not exploitable unless JavaScript is enabled.

A heap based buffer overflow flaw was found in the handling of
cancelled newsgroup messages. If the user cancels a specially crafted
newsgroup message it could cause Thunderbird to crash or, potentially,
execute arbitrary code as the user running Thunderbird.
(CVE-2008-4070)

All Thunderbird users should upgrade to these updated packages, which
resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015292.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e2f1969"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015293.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68206118"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6f006b16"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c51af6b2"
  );
  # http://lists.centos.org/pipermail/centos-announce/2008-October/015307.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ce5c265"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(22, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.12-16.el4.centos")) flag++;

if (rpm_check(release:"CentOS-5", reference:"thunderbird-2.0.0.17-1.el5.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
