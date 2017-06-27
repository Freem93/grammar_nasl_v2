#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1436. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78411);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/02/21 14:37:42 $");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1992", "CVE-2013-1995", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2063", "CVE-2013-2064", "CVE-2013-2066", "CVE-2013-7439");
  script_bugtraq_id(60120, 60121, 60122, 60123, 60124, 60125, 60126, 60127, 60128, 60129, 60131, 60132, 60133, 60134, 60135, 60136, 60137, 60138, 60139, 60143, 60144, 60145, 60146, 60148);
  script_osvdb_id(93647, 93648, 93652, 93653, 93655, 93661, 93664, 93669, 93673, 93690);
  script_xref(name:"RHSA", value:"2014:1436");

  script_name(english:"RHEL 6 : X11 client libraries (RHSA-2014:1436)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated X11 client libraries packages that fix multiple security
issues, several bugs, and add various enhancements are now available
for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The X11 (Xorg) libraries provide library routines that are used within
all X Window applications.

Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way various X11 client libraries handled
certain protocol data. An attacker able to submit invalid protocol
data to an X11 server via a malicious X11 client could use either of
these flaws to potentially escalate their privileges on the system.
(CVE-2013-1981, CVE-2013-1982, CVE-2013-1983, CVE-2013-1984,
CVE-2013-1985, CVE-2013-1986, CVE-2013-1987, CVE-2013-1988,
CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-2003,
CVE-2013-2062, CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer
out-of-bounds write flaws, were found in the way various X11 client
libraries handled data returned from an X11 server. A malicious X11
server could possibly use this flaw to execute arbitrary code with the
privileges of the user running an X11 client. (CVE-2013-1997,
CVE-2013-1998, CVE-2013-1999, CVE-2013-2000, CVE-2013-2001,
CVE-2013-2002, CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices()
function of X.Org X11's libXi runtime library handled signed numbers.
A malicious X11 server could possibly use this flaw to execute
arbitrary code with the privileges of the user running an X11 client.
(CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used
uninitialized pointers. A malicious X11 server could possibly use this
flaw to execute arbitrary code with the privileges of the user running
an X11 client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11,
the Core X11 protocol client library, processed certain user-specified
files. A malicious X11 server could possibly use this flaw to crash an
X11 client via a specially crafted file. (CVE-2013-2004)

The xkeyboard-config package has been upgraded to upstream version
2.11, which provides a number of bug fixes and enhancements over the
previous version. (BZ#1077471)

This update also fixes the following bugs :

* Previously, updating the mesa-libGL package did not update the
libX11 package, although it was listed as a dependency of mesa-libGL.
This bug has been fixed and updating mesa-libGL now updates all
dependent packages as expected. (BZ#1054614)

* Previously, closing a customer application could occasionally cause
the X Server to terminate unexpectedly. After this update, the X
Server no longer hangs when a user closes a customer application.
(BZ#971626)

All X11 client libraries users are advised to upgrade to these updated
packages, which correct these issues and add these enhancements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1981.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1982.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1983.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1984.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1985.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1986.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1987.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1988.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1989.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1990.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1991.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1992.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1995.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1997.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1998.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-1999.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2004.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-2066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-7439.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.x.org/wiki/Development/Security/Advisory-2013-05-23/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-1436.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXext-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXinerama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXinerama-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXinerama-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86dga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86dga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdmx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdmx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libxcb-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xorg-x11-xtrans-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:1436";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL6", reference:"libX11-1.6.0-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libX11-common-1.6.0-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libX11-debuginfo-1.6.0-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libX11-devel-1.6.0-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXcursor-1.1.14-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXcursor-debuginfo-1.1.14-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXcursor-devel-1.1.14-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXext-1.3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXext-debuginfo-1.3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXext-devel-1.3.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXfixes-5.0.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXfixes-debuginfo-5.0.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXfixes-devel-5.0.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXi-1.7.2-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXi-debuginfo-1.7.2-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXi-devel-1.7.2-2.2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXinerama-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXinerama-debuginfo-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXinerama-devel-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXp-1.0.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXp-debuginfo-1.0.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXp-devel-1.0.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrandr-1.4.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrandr-debuginfo-1.4.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrandr-devel-1.4.1-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrender-0.9.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrender-debuginfo-0.9.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXrender-devel-0.9.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXres-1.0.7-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXres-debuginfo-1.0.7-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXres-devel-1.0.7-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXt-1.1.4-6.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXt-debuginfo-1.1.4-6.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXt-devel-1.1.4-6.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXtst-1.2.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXtst-debuginfo-1.2.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXtst-devel-1.2.2-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXv-1.0.9-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXv-debuginfo-1.0.9-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXv-devel-1.0.9-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libXvMC-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libXvMC-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libXvMC-debuginfo-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libXvMC-debuginfo-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libXvMC-devel-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libXvMC-devel-1.0.8-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86dga-1.1.4-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86dga-debuginfo-1.1.4-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86dga-devel-1.1.4-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86vm-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86vm-debuginfo-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libXxf86vm-devel-1.1.3-2.1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libdmx-1.1.3-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libdmx-debuginfo-1.1.3-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libdmx-devel-1.1.3-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libxcb-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libxcb-debuginfo-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libxcb-devel-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"libxcb-doc-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libxcb-python-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"libxcb-python-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libxcb-python-1.9.1-2.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xcb-proto-1.8-3.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xkeyboard-config-2.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xkeyboard-config-devel-2.11-1.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xorg-x11-proto-devel-7.7-9.el6")) flag++;
  if (rpm_check(release:"RHEL6", reference:"xorg-x11-xtrans-devel-1.3.4-1.el6")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11 / libX11-common / libX11-debuginfo / libX11-devel / etc");
  }
}
