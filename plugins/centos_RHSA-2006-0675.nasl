#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2006:0675 and 
# CentOS Errata and Security Advisory 2006:0675 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(22424);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-4253", "CVE-2006-4340", "CVE-2006-4565", "CVE-2006-4566", "CVE-2006-4567", "CVE-2006-4568", "CVE-2006-4569", "CVE-2006-4571");
  script_bugtraq_id(19488, 19849, 20042);
  script_osvdb_id(27974, 27975, 28843, 28844, 28845, 28846, 28847, 28848, 94476, 94477, 94478, 94479, 94480, 95338, 95339, 95340, 95341, 95911, 95912, 95913, 95914, 95915, 96645);
  script_xref(name:"RHSA", value:"2006:0675");

  script_name(english:"CentOS 4 : firefox (CESA-2006:0675)");
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

Two flaws were found in the way Firefox processed certain regular
expressions. A malicious web page could crash the browser or possibly
execute arbitrary code as the user running Firefox. (CVE-2006-4565,
CVE-2006-4566)

A number of flaws were found in Firefox. A malicious web page could
crash the browser or possibly execute arbitrary code as the user
running Firefox. (CVE-2006-4571)

A flaw was found in the handling of JavaScript timed events. A
malicious web page could crash the browser or possibly execute
arbitrary code as the user running Firefox. (CVE-2006-4253)

Daniel Bleichenbacher recently described an implementation error in
RSA signature verification. For RSA keys with exponent 3 it is
possible for an attacker to forge a signature that would be
incorrectly verified by the NSS library. Firefox as shipped trusts
several root Certificate Authorities that use exponent 3. An attacker
could have created a carefully crafted SSL certificate which be
incorrectly trusted when their site was visited by a victim.
(CVE-2006-4340)

A flaw was found in the Firefox auto-update verification system. An
attacker who has the ability to spoof a victim's DNS could get Firefox
to download and install malicious code. In order to exploit this issue
an attacker would also need to get a victim to previously accept an
unverifiable certificate. (CVE-2006-4567)

Firefox did not properly prevent a frame in one domain from injecting
content into a sub-frame that belongs to another domain, which
facilitates website spoofing and other attacks (CVE-2006-4568)

Firefox did not load manually opened, blocked popups in the right
domain context, which could lead to cross-site scripting attacks. In
order to exploit this issue an attacker would need to find a site
which would frame their malicious page and convince the user to
manually open a blocked popup. (CVE-2006-4569)

Users of Firefox are advised to upgrade to this update, which contains
Firefox version 1.5.0.7 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66e7710b"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013255.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdc64a15"
  );
  # http://lists.centos.org/pipermail/centos-announce/2006-September/013257.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7b24354b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 79, 119, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/22");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/12");
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
if (rpm_check(release:"CentOS-4", reference:"firefox-1.5.0.7-0.1.el4.centos4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
