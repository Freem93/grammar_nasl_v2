#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2009:1430 and 
# CentOS Errata and Security Advisory 2009:1430 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(40932);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/17 20:59:10 $");

  script_cve_id("CVE-2009-2470", "CVE-2009-2654", "CVE-2009-2662", "CVE-2009-2663", "CVE-2009-2664", "CVE-2009-2665", "CVE-2009-3069", "CVE-2009-3070", "CVE-2009-3071", "CVE-2009-3072", "CVE-2009-3073", "CVE-2009-3074", "CVE-2009-3075", "CVE-2009-3076", "CVE-2009-3077", "CVE-2009-3078", "CVE-2009-3079");
  script_bugtraq_id(35803, 36343);
  script_osvdb_id(57971, 57972, 57973, 57975, 57976, 57977, 57978, 57979, 57980);
  script_xref(name:"RHSA", value:"2009:1430");

  script_name(english:"CentOS 4 / 5 : firefox / seamonkey (CESA-2009:1430)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Red Hat Enterprise Linux 4 and 5.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox. nspr provides the
Netscape Portable Runtime (NSPR).

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2009-3070, CVE-2009-3071, CVE-2009-3072,
CVE-2009-3074, CVE-2009-3075)

A use-after-free flaw was found in Firefox. An attacker could use this
flaw to crash Firefox or, potentially, execute arbitrary code with the
privileges of the user running Firefox. (CVE-2009-3077)

A flaw was found in the way Firefox handles malformed JavaScript. A
website with an object containing malicious JavaScript could execute
that JavaScript with the privileges of the user running Firefox.
(CVE-2009-3079)

Descriptions in the dialogs when adding and removing PKCS #11 modules
were not informative. An attacker able to trick a user into installing
a malicious PKCS #11 module could use this flaw to install their own
Certificate Authority certificates on a user's machine, making it
possible to trick the user into believing they are viewing a trusted
site or, potentially, execute arbitrary code with the privileges of
the user running Firefox. (CVE-2009-3076)

A flaw was found in the way Firefox displays the address bar when
window.open() is called in a certain way. An attacker could use this
flaw to conceal a malicious URL, possibly tricking a user into
believing they are viewing a trusted site. (CVE-2009-2654)

A flaw was found in the way Firefox displays certain Unicode
characters. An attacker could use this flaw to conceal a malicious
URL, possibly tricking a user into believing they are viewing a
trusted site. (CVE-2009-3078)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 3.0.14. You can find a link to the
Mozilla advisories in the References section of this errata.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 3.0.14, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016133.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fde9c53d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016134.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b9ea776"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016163.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b2000f66"
  );
  # http://lists.centos.org/pipermail/centos-announce/2009-September/016164.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?339bf403"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 94, 119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xulrunner-devel-unstable");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-3.0.14-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-3.0.14-1.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-4.7.5-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-4.7.5-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"nspr-devel-4.7.5-1.el4_8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"nspr-devel-4.7.5-1.el4_8")) flag++;

if (rpm_check(release:"CentOS-5", reference:"firefox-3.0.14-1.el5.centos")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-4.7.5-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"nspr-devel-4.7.5-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-1.9.0.14-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-1.9.0.14-1.el5_4")) flag++;
if (rpm_check(release:"CentOS-5", reference:"xulrunner-devel-unstable-1.9.0.14-1.el5_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
