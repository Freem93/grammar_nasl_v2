#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:586 and 
# CentOS Errata and Security Advisory 2005:586 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(21949);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/05/19 23:25:24 $");

  script_cve_id("CVE-2004-0718", "CVE-2005-1937", "CVE-2005-2114", "CVE-2005-2260", "CVE-2005-2261", "CVE-2005-2262", "CVE-2005-2263", "CVE-2005-2264", "CVE-2005-2265", "CVE-2005-2266", "CVE-2005-2267", "CVE-2005-2268", "CVE-2005-2269", "CVE-2005-2270");
  script_osvdb_id(17397, 17913, 17942, 17964, 17966, 17967, 17968, 17969, 17970, 17971, 59834, 77534, 79188, 79395);
  script_xref(name:"RHSA", value:"2005:586");

  script_name(english:"CentOS 4 : firefox (CESA-2005:586)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated firefox package that fixes various security bugs is now
available for Red Hat Enterprise Linux 4.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

Mozilla Firefox is an open source Web browser.

A bug was found in the way Firefox handled synthetic events. It is
possible that Web content could generate events such as keystrokes or
mouse clicks that could be used to steal data or execute malicious
JavaScript code. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-2260 to this issue.

A bug was found in the way Firefox executed JavaScript in XBL
controls. It is possible for a malicious webpage to leverage this
vulnerability to execute other JavaScript based attacks even when
JavaScript is disabled. (CVE-2005-2261)

A bug was found in the way Firefox set an image as the desktop
wallpaper. If a user chooses the 'Set As Wallpaper...' context menu
item on a specially crafted image, it is possible for an attacker to
execute arbitrary code on a victim's machine. (CVE-2005-2262)

A bug was found in the way Firefox installed its extensions. If a user
can be tricked into visiting a malicious webpage, it may be possible
to obtain sensitive information such as cookies or passwords.
(CVE-2005-2263)

A bug was found in the way Firefox handled the _search target. It is
possible for a malicious website to inject JavaScript into an already
open webpage. (CVE-2005-2264)

A bug was found in the way Firefox handled certain JavaScript
functions. It is possible for a malicious web page to crash the
browser by executing malformed JavaScript code. (CVE-2005-2265)

A bug was found in the way Firefox handled multiple frame domains. It
is possible for a frame as part of a malicious website to inject
content into a frame that belongs to another domain. This issue was
previously fixed as CVE-2004-0718 but was accidentally disabled.
(CVE-2005-1937)

A bug was found in the way Firefox handled child frames. It is
possible for a malicious framed page to steal sensitive information
from its parent page. (CVE-2005-2266)

A bug was found in the way Firefox opened URLs from media players. If
a media player opens a URL that is JavaScript, JavaScript is executed
with access to the currently open webpage. (CVE-2005-2267)

A design flaw was found in the way Firefox displayed alerts and
prompts. Alerts and prompts were given the generic title [JavaScript
Application] which prevented a user from knowing which site created
them. (CVE-2005-2268)

A bug was found in the way Firefox handled DOM node names. It is
possible for a malicious site to overwrite a DOM node name, allowing
certain privileged chrome actions to execute the malicious JavaScript.
(CVE-2005-2269)

A bug was found in the way Firefox cloned base objects. It is possible
for Web content to navigate up the prototype chain to gain access to
privileged chrome objects. (CVE-2005-2270)

Users of Firefox are advised to upgrade to this updated package that
contains Firefox version 1.0.6 and is not vulnerable to these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011942.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7fa117b8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011949.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?24b97a67"
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-July/011950.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5e7057e3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Suite/Firefox compareTo() Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/05");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"firefox-1.0.6-1.4.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"firefox-1.0.6-1.4.1.centos4")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"firefox-1.0.6-1.4.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
