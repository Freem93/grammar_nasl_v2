#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0139. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72364);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/06 15:40:56 $");

  script_cve_id("CVE-2012-6152", "CVE-2013-6477", "CVE-2013-6478", "CVE-2013-6479", "CVE-2013-6481", "CVE-2013-6482", "CVE-2013-6483", "CVE-2013-6484", "CVE-2013-6485", "CVE-2013-6487", "CVE-2013-6489", "CVE-2013-6490", "CVE-2014-0020");
  script_bugtraq_id(65188, 65192, 65195, 65243);
  script_osvdb_id(102614, 102615, 102616, 102617, 102618, 102619, 102620, 102621, 102622, 102623, 102625, 102626, 102627, 102628, 102629);
  script_xref(name:"RHSA", value:"2014:0139");

  script_name(english:"RHEL 5 / 6 : pidgin (RHSA-2014:0139)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pidgin packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Pidgin is an instant messaging program which can log in to multiple
accounts on multiple instant messaging networks simultaneously.

A heap-based buffer overflow flaw was found in the way Pidgin
processed certain HTTP responses. A malicious server could send a
specially crafted HTTP response, causing Pidgin to crash or
potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6485)

Multiple heap-based buffer overflow flaws were found in several
protocol plug-ins in Pidgin (Gadu-Gadu, MXit, SIMPLE). A malicious
server could send a specially crafted message, causing Pidgin to crash
or potentially execute arbitrary code with the permissions of the user
running Pidgin. (CVE-2013-6487, CVE-2013-6489, CVE-2013-6490)

Multiple denial of service flaws were found in several protocol
plug-ins in Pidgin (Yahoo!, XMPP, MSN, stun, IRC). A remote attacker
could use these flaws to crash Pidgin by sending a specially crafted
message. (CVE-2012-6152, CVE-2013-6477, CVE-2013-6481, CVE-2013-6482,
CVE-2013-6484, CVE-2014-0020)

It was found that the Pidgin XMPP protocol plug-in did not verify the
origin of 'iq' replies. A remote attacker could use this flaw to spoof
an 'iq' reply, which could lead to injection of fake data or cause
Pidgin to crash via a NULL pointer dereference. (CVE-2013-6483)

A flaw was found in the way Pidgin parsed certain HTTP response
headers. A remote attacker could use this flaw to crash Pidgin via a
specially crafted HTTP response header. (CVE-2013-6479)

It was found that Pidgin crashed when a mouse pointer was hovered over
a long URL. A remote attacker could use this flaw to crash Pidgin by
sending a message containing a long URL string. (CVE-2013-6478)

Red Hat would like to thank the Pidgin project for reporting these
issues. Upstream acknowledges Thijs Alkemade, Robert Vehse, Jaime
Breva Ribes, Jacob Appelbaum of the Tor Project, Daniel Atallah,
Fabian Yamaguchi and Christian Wressnegger of the University of
Goettingen, Matt Jones of Volvent, and Yves Younan, Ryan Pentney, and
Pawel Janic of Sourcefire VRT as the original reporters of these
issues.

All pidgin users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. Pidgin must
be restarted for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-6152.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6481.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6482.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6483.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6484.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6485.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6487.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6489.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2013-6490.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2014-0020.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.pidgin.im/news/security/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2014-0139.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:finch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libpurple-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pidgin-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.5");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/06");
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
if (! ereg(pattern:"^(5|6)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x / 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2014:0139";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"finch-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"finch-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-perl-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-perl-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"libpurple-tcl-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"libpurple-tcl-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-debuginfo-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-debuginfo-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-devel-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"pidgin-perl-2.6.6-32.el5")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"pidgin-perl-2.6.6-32.el5")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"finch-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"finch-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-perl-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-perl-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"libpurple-tcl-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"libpurple-tcl-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-debuginfo-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-debuginfo-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-devel-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-docs-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-docs-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"pidgin-perl-2.7.9-27.el6")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"pidgin-perl-2.7.9-27.el6")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "finch / finch-devel / libpurple / libpurple-devel / libpurple-perl / etc");
  }
}
