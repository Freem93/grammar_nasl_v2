#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0734 and 
# CentOS Errata and Security Advisory 2006:0734 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(36309);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/04 14:30:40 $");

  script_cve_id("CVE-2006-5462", "CVE-2006-5463", "CVE-2006-5464", "CVE-2006-5747", "CVE-2006-5748");
  script_bugtraq_id(19849);
  script_osvdb_id(29013, 30300, 30301, 30302, 30303);
  script_xref(name:"RHSA", value:"2006:0734");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2006:0734)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security bugs are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several flaws were found in the way SeaMonkey processes certain
malformed JavaScript code. A malicious web page could cause the
execution of JavaScript code in such a way that could cause SeaMonkey
to crash or execute arbitrary code as the user running SeaMonkey.
(CVE-2006-5463, CVE-2006-5747, CVE-2006-5748)

Several flaws were found in the way SeaMonkey renders web pages. A
malicious web page could cause the browser to crash or possibly
execute arbitrary code as the user running SeaMonkey. (CVE-2006-5464)

A flaw was found in the way SeaMonkey verifies RSA signatures. For RSA
keys with exponent 3 it is possible for an attacker to forge a
signature that would be incorrectly verified by the NSS library.
SeaMonkey as shipped trusts several root Certificate Authorities that
use exponent 3. An attacker could have created a carefully crafted SSL
certificate which be incorrectly trusted when their site was visited
by a victim. This flaw was previously thought to be fixed in SeaMonkey
1.0.5, however Ulrich Kuehn discovered the fix was incomplete
(CVE-2006-5462)

Users of SeaMonkey are advised to upgrade to these erratum packages,
which contains SeaMonkey version 1.0.6 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013368.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e62feb0"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013370.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9a0c3299"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013371.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d59bb3ff"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013376.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8b9a4a58"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013379.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57156a5b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-November/013380.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7955077c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:seamonkey-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
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
if (rpm_check(release:"CentOS-3", reference:"seamonkey-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-chat-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-devel-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-dom-inspector-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-js-debugger-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-mail-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-devel-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-1.0.6-0.1.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-devel-1.0.6-0.1.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.10-0.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.10-0.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.10-0.5.el4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-chat-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-devel-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-dom-inspector-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-js-debugger-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-mail-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nspr-devel-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-1.0.6-0.1.el4.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"seamonkey-nss-devel-1.0.6-0.1.el4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
