#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0329 and 
# CentOS Errata and Security Advisory 2006:0329 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21898);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-0748", "CVE-2006-0749", "CVE-2006-0884", "CVE-2006-1724", "CVE-2006-1727", "CVE-2006-1728", "CVE-2006-1729", "CVE-2006-1730", "CVE-2006-1731", "CVE-2006-1732", "CVE-2006-1733", "CVE-2006-1734", "CVE-2006-1735", "CVE-2006-1737", "CVE-2006-1738", "CVE-2006-1739", "CVE-2006-1740", "CVE-2006-1741", "CVE-2006-1742", "CVE-2006-1790");
  script_osvdb_id(24658, 24659, 24660, 24661, 24662, 24663, 24664, 24666, 24667, 24668, 24669, 24670, 24671, 24677, 24678, 24679, 24680);
  script_xref(name:"RHSA", value:"2006:0329");

  script_name(english:"CentOS 3 / 4 : mozilla (CESA-2006:0329)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mozilla packages that fix several security bugs are now
available.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 24 Apr 2006] The erratum text has been updated to include the
details of additional issues that were fixed by these erratum packages
but which were not public at the time of release. No changes have been
made to the packages.

Mozilla is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

Several bugs were found in the way Mozilla processes malformed
JavaScript. A malicious web page could modify the content of a
different open web page, possibly stealing sensitive information or
conducting a cross-site scripting attack. (CVE-2006-1731,
CVE-2006-1732, CVE-2006-1741)

Several bugs were found in the way Mozilla processes certain
JavaScript actions. A malicious web page could execute arbitrary
JavaScript instructions with the permissions of 'chrome', allowing the
page to steal sensitive information or install browser malware.
(CVE-2006-1727, CVE-2006-1728, CVE-2006-1733, CVE-2006-1734,
CVE-2006-1735, CVE-2006-1742)

Several bugs were found in the way Mozilla processes malformed web
pages. A carefully crafted malicious web page could cause the
execution of arbitrary code as the user running Mozilla.
(CVE-2006-0748, CVE-2006-0749, CVE-2006-1730, CVE-2006-1737,
CVE-2006-1738, CVE-2006-1739, CVE-2006-1790)

A bug was found in the way Mozilla displays the secure site icon. If a
browser is configured to display the non-default secure site modal
warning dialog, it may be possible to trick a user into believing they
are viewing a secure site. (CVE-2006-1740)

A bug was found in the way Mozilla allows JavaScript mutation events
on 'input' form elements. A malicious web page could be created in
such a way that when a user submits a form, an arbitrary file could be
uploaded to the attacker. (CVE-2006-1729)

A bug was found in the way Mozilla executes in-line mail forwarding.
If a user can be tricked into forwarding a maliciously crafted mail
message as in-line content, it is possible for the message to execute
JavaScript with the permissions of 'chrome'. (CVE-2006-0884)

Users of Mozilla are advised to upgrade to these updated packages
containing Mozilla version 1.7.13 which corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68804485"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca34cdd8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?719425dc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?89fa6b56"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a95e0314"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-April/012830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?40793133"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 79, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-chat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-dom-inspector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-js-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-3", reference:"mozilla-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-chat-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-devel-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-dom-inspector-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-js-debugger-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-mail-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nspr-devel-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-1.7.13-1.1.3.1.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"mozilla-nss-devel-1.7.13-1.1.3.1.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-0.9.2-2.4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-0.9.2-2.4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"devhelp-devel-0.9.2-2.4.8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"devhelp-devel-0.9.2-2.4.8")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-chat-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-devel-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-dom-inspector-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-js-debugger-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-mail-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nspr-devel-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-1.7.13-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", reference:"mozilla-nss-devel-1.7.13-1.4.1.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
