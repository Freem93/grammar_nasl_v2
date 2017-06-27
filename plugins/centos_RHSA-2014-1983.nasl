#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1983 and 
# CentOS Errata and Security Advisory 2014:1983 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(79879);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/06/15 16:38:22 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2014-8103");
  script_bugtraq_id(71595, 71596, 71597, 71598, 71599, 71600, 71601, 71602, 71603, 71604, 71605, 71606, 71608);
  script_osvdb_id(115603, 115604, 115605, 115606, 115607, 115608, 115609, 115610, 115611, 115612, 115613, 115614, 115615);
  script_xref(name:"RHSA", value:"2014:1983");

  script_name(english:"CentOS 6 / 7 : xorg-x11-server (CESA-2014:1983)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated xorg-x11-server packages that fix multiple security issues are
now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

X.Org is an open source implementation of the X Window System. It
provides the basic low-level functionality that full-fledged graphical
user interfaces are designed upon.

Multiple integer overflow flaws and out-of-bounds write flaws were
found in the way the X.Org server calculated memory requirements for
certain X11 core protocol and GLX extension requests. A malicious,
authenticated client could use either of these flaws to crash the
X.Org server or, potentially, execute arbitrary code with root
privileges. (CVE-2014-8092, CVE-2014-8093, CVE-2014-8098)

It was found that the X.Org server did not properly handle SUN-DES-1
(Secure RPC) authentication credentials. A malicious, unauthenticated
client could use this flaw to crash the X.Org server by submitting a
specially crafted authentication request. (CVE-2014-8091)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server, or leak memory contents to the client.
(CVE-2014-8097)

An integer overflow flaw was found in the way the X.Org server
calculated memory requirements for certain DRI2 extension requests. A
malicious, authenticated client could use this flaw to crash the X.Org
server. (CVE-2014-8094)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server. (CVE-2014-8095, CVE-2014-8096, CVE-2014-8099,
CVE-2014-8100, CVE-2014-8101, CVE-2014-8102, CVE-2014-8103)

All xorg-x11-server users are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c66a0d03"
  );
  # http://lists.centos.org/pipermail/centos-announce/2014-December/020824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c120b54a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xorg-x11-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xdmx-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xephyr-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xnest-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xorg-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-Xvfb-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-common-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-devel-1.15.0-25.el6.centos")) flag++;
if (rpm_check(release:"CentOS-6", reference:"xorg-x11-server-source-1.15.0-25.el6.centos")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"xorg-x11-server-source-1.15.0-7.el7_0.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
