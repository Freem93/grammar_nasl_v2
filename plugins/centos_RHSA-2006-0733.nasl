#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0733 and 
# CentOS Errata and Security Advisory 2006:0733 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(37577);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_osvdb_id(29013, 30300, 30301, 30302, 30303);
  script_xref(name:"RHSA", value:"2006:0733");

  script_name(english:"CentOS 4 : firefox (CESA-2006:0733)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

Several flaws were found in the way Firefox processes certain
malformed JavaScript code. A malicious web page could cause the
execution of JavaScript code in such a way that could cause Firefox to
crash or execute arbitrary code as the user running Firefox.
(CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way Firefox renders web pages. A
malicious web page could cause the browser to crash or possibly
execute arbitrary code as the user running Firefox. (CVE-2006-5464)

A flaw was found in the way Firefox verifies RSA signatures. For RSA
keys with exponent 3 it is possible for an attacker to forge a
signature that would be incorrectly verified by the NSS library.
Firefox as shipped trusts several root Certificate Authorities that
use exponent 3. An attacker could have created a carefully crafted SSL
certificate which be incorrectly trusted when their site was visited
by a victim. This flaw was previously thought to be fixed in Firefox
1.5.0.7, however Ulrich Kuehn discovered the fix was incomplete
(CVE-2006-5462)

Users of Firefox are advised to upgrade to these erratum packages,
which contain Firefox version 1.5.0.8 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013378.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c0cc5c33"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013381.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca221936"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013382.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af81a7b8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/14");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.8-0.1.el4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
