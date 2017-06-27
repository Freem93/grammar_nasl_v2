#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0516. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58868);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2011-3062", "CVE-2012-0467", "CVE-2012-0468", "CVE-2012-0469", "CVE-2012-0470", "CVE-2012-0471", "CVE-2012-0472", "CVE-2012-0473", "CVE-2012-0474", "CVE-2012-0477", "CVE-2012-0478", "CVE-2012-0479");
  script_bugtraq_id(53218, 53219, 53220, 53221, 53222, 53223, 53224, 53225, 53227, 53228, 53229, 53231);
  script_osvdb_id(80740, 81513, 81514, 81515, 81516, 81517, 81518, 81519, 81520, 81522, 81523, 81524);
  script_xref(name:"RHSA", value:"2012:0516");

  script_name(english:"RHEL 5 / 6 : thunderbird (RHSA-2012:0516)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated thunderbird package that fixes multiple security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

A flaw was found in Sanitiser for OpenType (OTS), used by Thunderbird
to help prevent potential exploits in malformed OpenType fonts.
Malicious content could cause Thunderbird to crash or, under certain
conditions, possibly execute arbitrary code with the privileges of the
user running Thunderbird. (CVE-2011-3062)

Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-0467, CVE-2012-0468, CVE-2012-0469)

Content containing a malicious Scalable Vector Graphics (SVG) image
file could cause Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-0470)

A flaw was found in the way Thunderbird used its embedded Cairo
library to render certain fonts. Malicious content could cause
Thunderbird to crash or, under certain conditions, possibly execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-0472)

A flaw was found in the way Thunderbird rendered certain images using
WebGL. Malicious content could cause Thunderbird to crash or, under
certain conditions, possibly execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-0478)

A cross-site scripting (XSS) flaw was found in the way Thunderbird
handled certain multibyte character sets. Malicious content could
cause Thunderbird to run JavaScript code with the permissions of
different content. (CVE-2012-0471)

A flaw was found in the way Thunderbird rendered certain graphics
using WebGL. Malicious content could cause Thunderbird to crash.
(CVE-2012-0473)

A flaw in the built-in feed reader in Thunderbird allowed the Website
field to display the address of different content than the content the
user was visiting. An attacker could use this flaw to conceal a
malicious URL, possibly tricking a user into believing they are
viewing a trusted site, or allowing scripts to be loaded from the
attacker's site, possibly leading to cross-site scripting (XSS)
attacks. (CVE-2012-0474)

A flaw was found in the way Thunderbird decoded the ISO-2022-KR and
ISO-2022-CN character sets. Malicious content could cause Thunderbird
to run JavaScript code with the permissions of different content.
(CVE-2012-0477)

A flaw was found in the way the built-in feed reader in Thunderbird
handled RSS and Atom feeds. Invalid RSS or Atom content loaded over
HTTPS caused Thunderbird to display the address of said content, but
not the content. The previous content continued to be displayed. An
attacker could use this flaw to perform phishing attacks, or trick
users into thinking they are visiting the site reported by the Website
field, when the page is actually content controlled by an attacker.
(CVE-2012-0479)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Mateusz Jurczyk of the Google Security
Team as the original reporter of CVE-2011-3062; Aki Helin from OUSPG
as the original reporter of CVE-2012-0469; Atte Kettunen from OUSPG as
the original reporter of CVE-2012-0470; wushi of team509 via iDefense
as the original reporter of CVE-2012-0472; Ms2ger as the original
reporter of CVE-2012-0478; Anne van Kesteren of Opera Software as the
original reporter of CVE-2012-0471; Matias Juntunen as the original
reporter of CVE-2012-0473; Jordi Chancel and Eddy Bordi, and Chris
McGowen as the original reporters of CVE-2012-0474; Masato Kinugawa as
the original reporter of CVE-2012-0477; and Jeroen van der Gun as the
original reporter of CVE-2012-0479.

Note: All issues except CVE-2012-0470, CVE-2012-0472, and
CVE-2011-3062 cannot be exploited by a specially crafted HTML mail
message as JavaScript is disabled by default for mail messages. It
could be exploited another way in Thunderbird, for example, when
viewing the full remote content of an RSS feed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-3062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0467.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0468.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0469.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0470.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0471.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0472.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0473.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0474.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0477.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0478.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-0479.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0516.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected thunderbird and / or thunderbird-debuginfo
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:thunderbird-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
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
  rhsa = "RHSA-2012:0516";
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
  if (rpm_check(release:"RHEL5", cpu:"i386", reference:"thunderbird-10.0.4-1.el5_8")) flag++;

  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"thunderbird-10.0.4-1.el5_8")) flag++;


  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-10.0.4-1.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-10.0.4-1.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-10.0.4-1.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"thunderbird-debuginfo-10.0.4-1.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"thunderbird-debuginfo-10.0.4-1.el6_2")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"thunderbird-debuginfo-10.0.4-1.el6_2")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird / thunderbird-debuginfo");
  }
}
