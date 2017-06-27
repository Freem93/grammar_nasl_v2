#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0217. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64391);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2010-4008", "CVE-2010-4494", "CVE-2011-0216", "CVE-2011-1944", "CVE-2011-2821", "CVE-2011-2834", "CVE-2011-3102", "CVE-2011-3905", "CVE-2011-3919", "CVE-2012-0841", "CVE-2012-5134");
  script_osvdb_id(69205, 69673, 73248, 73994, 74695, 75560, 77707, 78148, 79437, 81964, 87882);
  script_xref(name:"RHSA", value:"2013:0217");

  script_name(english:"RHEL 6 : mingw32-libxml2 (RHSA-2013:0217)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated mingw32-libxml2 packages that fix several security issues are
now available for Red Hat Enterprise Linux 6. This advisory also
contains information about future updates for the mingw32 packages, as
well as the deprecation of the packages with the release of Red Hat
Enterprise Linux 6.4.

The Red Hat Security Response Team has rated this update as having
important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

These packages provide the libxml2 library, a development toolbox
providing the implementation of various XML standards, for users of
MinGW (Minimalist GNU for Windows).

IMPORTANT NOTE: The mingw32 packages in Red Hat Enterprise Linux 6
will no longer be updated proactively and will be deprecated with the
release of Red Hat Enterprise Linux 6.4. These packages were provided
to support other capabilities in Red Hat Enterprise Linux and were not
intended for direct customer use. Customers are advised to not use
these packages with immediate effect. Future updates to these packages
will be at Red Hat's discretion and these packages may be removed in a
future minor release.

A heap-based buffer overflow flaw was found in the way libxml2 decoded
entity references with long names. A remote attacker could provide a
specially crafted XML file that, when opened in an application linked
against libxml2, would cause the application to crash or, potentially,
execute arbitrary code with the privileges of the user running the
application. (CVE-2011-3919)

A heap-based buffer underflow flaw was found in the way libxml2
decoded certain entities. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2012-5134)

It was found that the hashing routine used by libxml2 arrays was
susceptible to predictable hash collisions. Sending a specially
crafted message to an XML service could result in longer processing
time, which could lead to a denial of service. To mitigate this issue,
randomization has been added to the hashing function to reduce the
chance of an attacker successfully causing intentional collisions.
(CVE-2012-0841)

Multiple flaws were found in the way libxml2 parsed certain XPath (XML
Path Language) expressions. If an attacker were able to supply a
specially crafted XML file to an application using libxml2, as well as
an XPath expression for that application to run against the crafted
file, it could cause the application to crash. (CVE-2010-4008,
CVE-2010-4494, CVE-2011-2821, CVE-2011-2834)

Two heap-based buffer overflow flaws were found in the way libxml2
decoded certain XML files. A remote attacker could provide a specially
crafted XML file that, when opened in an application linked against
libxml2, would cause the application to crash or, potentially, execute
arbitrary code with the privileges of the user running the
application. (CVE-2011-0216, CVE-2011-3102)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way libxml2 parsed certain XPath expressions. If an
attacker were able to supply a specially crafted XML file to an
application using libxml2, as well as an XPath expression for that
application to run against the crafted file, it could cause the
application to crash or, possibly, execute arbitrary code.
(CVE-2011-1944)

An out-of-bounds memory read flaw was found in libxml2. A remote
attacker could provide a specially crafted XML file that, when opened
in an application linked against libxml2, would cause the application
to crash. (CVE-2011-3905)

Red Hat would like to thank the Google Security Team for reporting the
CVE-2010-4008 issue. Upstream acknowledges Bui Quang Minh from Bkis as
the original reporter of CVE-2010-4008.

All users of mingw32-libxml2 are advised to upgrade to these updated
packages, which contain backported patches to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4008.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4494.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0216.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1944.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2821.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2834.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3102.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3905.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3919.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0841.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-5134.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0217.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mingw32-libxml2, mingw32-libxml2-debuginfo and /
or mingw32-libxml2-static packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-libxml2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-libxml2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-libxml2-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2013:0217";
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
  if (rpm_check(release:"RHEL6", reference:"mingw32-libxml2-2.7.6-6.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mingw32-libxml2-debuginfo-2.7.6-6.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", reference:"mingw32-libxml2-static-2.7.6-6.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw32-libxml2 / mingw32-libxml2-debuginfo / etc");
  }
}
