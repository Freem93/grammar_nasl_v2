#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0078 and 
# CentOS Errata and Security Advisory 2007:0078 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(24763);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2006-6077", "CVE-2007-0008", "CVE-2007-0009", "CVE-2007-0775", "CVE-2007-0777", "CVE-2007-0778", "CVE-2007-0779", "CVE-2007-0780", "CVE-2007-0800", "CVE-2007-0981", "CVE-2007-0994", "CVE-2007-0995", "CVE-2007-0996", "CVE-2007-1092", "CVE-2007-1282");
  script_bugtraq_id(21240, 22396, 22566, 22679, 22694);
  script_osvdb_id(30641, 32103, 32104, 32105, 32106, 32107, 32108, 32109, 32110, 32111, 32112, 32114, 32115, 33810, 33811, 33812, 79165);
  script_xref(name:"RHSA", value:"2007:0078");

  script_name(english:"CentOS 4 : thunderbird (CESA-2007:0078)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated thunderbird packages that fix several security bugs are now
available for Red Hat Enterprise Linux 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

[Updated 06 March 2007] Updated text description to add CVE-2007-1282
and remove CVE-2007-0994, which was mistakenly listed as affecting
Thunderbird. No changes have been made to these erratum packages.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the way Thunderbird processed certain
malformed JavaScript code. A malicious HTML mail message could execute
JavaScript code in such a way that may result in Thunderbird crashing
or executing arbitrary code as the user running Thunderbird.
JavaScript support is disabled by default in Thunderbird; these issues
are not exploitable unless the user has enabled JavaScript.
(CVE-2007-0775, CVE-2007-0777, CVE-2007-1092)

A flaw was found in the way Thunderbird processed text/enhanced and
text/richtext formatted mail message. A specially crafted mail message
could execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2007-1282)

Several cross-site scripting (XSS) flaws were found in the way
Thunderbird processed certain malformed HTML mail messages. A
malicious HTML mail message could display misleading information which
may result in a user unknowingly divulging sensitive information such
as a password. (CVE-2006-6077, CVE-2007-0995, CVE-2007-0996)

A flaw was found in the way Thunderbird cached web content on the
local disk. A malicious HTML mail message may be able to inject
arbitrary HTML into a browsing session if the user reloads a targeted
site. (CVE-2007-0778)

A flaw was found in the way Thunderbird displayed certain web content.
A malicious HTML mail message could generate content which could
overlay user interface elements such as the hostname and security
indicators, tricking a user into thinking they are visiting a
different site. (CVE-2007-0779)

Two flaws were found in the way Thunderbird displayed blocked popup
windows. If a user can be convinced to open a blocked popup, it is
possible to read arbitrary local files, or conduct an XSS attack
against the user. (CVE-2007-0780, CVE-2007-0800)

Two buffer overflow flaws were found in the Network Security Services
(NSS) code for processing the SSLv2 protocol. Connecting to a
malicious secure web server could cause the execution of arbitrary
code as the user running Thunderbird. (CVE-2007-0008, CVE-2007-0009)

A flaw was found in the way Thunderbird handled the
'location.hostname' value during certain browser domain checks. This
flaw could allow a malicious HTML mail message to set domain cookies
for an arbitrary site, or possibly perform an XSS attack.
(CVE-2007-0981)

Users of Thunderbird are advised to apply this update, which contains
Thunderbird version 1.5.0.10 that corrects these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013588.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b16fa5c"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013589.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?76113583"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-March/013590.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da768dde"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", reference:"thunderbird-1.5.0.10-0.1.el4.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
