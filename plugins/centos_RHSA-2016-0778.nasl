#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0778 and 
# CentOS Errata and Security Advisory 2016:0778 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91168);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/17 17:13:10 $");

  script_cve_id("CVE-2015-5234", "CVE-2015-5235");
  script_osvdb_id(127019, 127031);
  script_xref(name:"RHSA", value:"2016:0778");

  script_name(english:"CentOS 6 : icedtea-web (CESA-2016:0778)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for icedtea-web is now available for Red Hat Enterprise
Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations. IcedTea-Web now also
contains PolicyEditor - a simple tool to configure Java policies.

The following packages have been upgraded to a newer upstream version:
icedtea-web (1.6.2). (BZ#1275523)

Security Fix(es) :

* It was discovered that IcedTea-Web did not properly sanitize applet
URLs when storing applet trust settings. A malicious web page could
use this flaw to inject trust-settings configuration, and cause
applets to be executed without user approval. (CVE-2015-5234)

* It was discovered that IcedTea-Web did not properly determine an
applet's origin when asking the user if the applet should be run. A
malicious page could use this flaw to cause IcedTea-Web to execute the
applet without user approval, or confuse the user into approving
applet execution based on an incorrectly indicated applet origin.
(CVE-2015-5235)

Red Hat would like to thank Andrea Palazzo (Truel IT) for reporting
these issues.

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.8 Release Notes and Red Hat Enterprise Linux 6.8
Technical Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2016-May/002834.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?41fd898a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icedtea-web packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/17");
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
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-1.6.2-1.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"icedtea-web-javadoc-1.6.2-1.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
