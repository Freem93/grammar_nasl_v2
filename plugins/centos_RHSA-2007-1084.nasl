#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:1084 and 
# CentOS Errata and Security Advisory 2007:1084 respectively.
#

include("compat.inc");

if (description)
{
  script_id(36661);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/11/17 20:59:08 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_osvdb_id(38463, 38867, 38868);
  script_xref(name:"RHSA", value:"2007:1084");

  script_name(english:"CentOS 3 / 4 : seamonkey (CESA-2007:1084)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated SeaMonkey packages that fix several security issues are now
available for Red Hat Enterprise Linux 2.1, 3, and 4.

This update has been rated as having critical security impact by the
Red Hat Security Response Team.

SeaMonkey is an open source Web browser, advanced email and newsgroup
client, IRC chat client, and HTML editor.

A cross-site scripting flaw was found in the way SeaMonkey handled the
jar: URI scheme. It was possible for a malicious website to leverage
this flaw and conduct a cross-site scripting attack against a user
running SeaMonkey. (CVE-2007-5947)

Several flaws were found in the way SeaMonkey processed certain
malformed web content. A webpage containing malicious content could
cause SeaMonkey to crash, or potentially execute arbitrary code as the
user running SeaMonkey. (CVE-2007-5959)

A race condition existed when SeaMonkey set the 'window.location'
property for a webpage. This flaw could allow a webpage to set an
arbitrary Referer header, which may lead to a Cross-site Request
Forgery (CSRF) attack against websites that rely only on the Referer
header for protection. (CVE-2007-5960)

Users of SeaMonkey are advised to upgrade to these updated packages,
which contain backported patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014458.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ad227b5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014459.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?58d85d69"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014460.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dd8ace08"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-November/014472.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e5beed8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected seamonkey packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/04/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/09");
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
if (rpm_check(release:"CentOS-3", reference:"seamonkey-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-chat-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-devel-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-dom-inspector-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-js-debugger-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-mail-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nspr-devel-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-1.0.9-0.7.el3.centos3")) flag++;
if (rpm_check(release:"CentOS-3", reference:"seamonkey-nss-devel-1.0.9-0.7.el3.centos3")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-chat-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-devel-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-dom-inspector-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-js-debugger-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-mail-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-nspr-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-nspr-devel-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-nss-1.0.9-7.el4.centos")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"seamonkey-nss-devel-1.0.9-7.el4.centos")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");