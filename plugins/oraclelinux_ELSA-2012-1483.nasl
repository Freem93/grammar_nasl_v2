#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:1483 and 
# Oracle Linux Security Advisory ELSA-2012-1483 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68660);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:02:15 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4202", "CVE-2012-4207", "CVE-2012-4209", "CVE-2012-4214", "CVE-2012-4215", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5830", "CVE-2012-5833", "CVE-2012-5835", "CVE-2012-5839", "CVE-2012-5840", "CVE-2012-5841", "CVE-2012-5842");
  script_bugtraq_id(56607);
  script_osvdb_id(87581, 87582, 87583, 87585, 87587, 87588, 87594, 87595, 87596, 87598, 87601, 87606, 87607, 87608, 87609);
  script_xref(name:"RHSA", value:"2012:1483");

  script_name(english:"Oracle Linux 6 : thunderbird (ELSA-2012-1483)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:1483 :

An updated thunderbird package that fixes several security issues is
now available for Red Hat Enterprise Linux 5 and 6.

The Red Hat Security Response Team has rated this update as having
critical security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-4214, CVE-2012-4215, CVE-2012-4216,
CVE-2012-5829, CVE-2012-5830, CVE-2012-5833, CVE-2012-5835,
CVE-2012-5839, CVE-2012-5840, CVE-2012-5842)

A buffer overflow flaw was found in the way Thunderbird handled GIF
(Graphics Interchange Format) images. Content containing a malicious
GIF image could cause Thunderbird to crash or, possibly, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-4202)

A flaw was found in the way Thunderbird decoded the HZ-GB-2312
character encoding. Malicious content could cause Thunderbird to run
JavaScript code with the permissions of different content.
(CVE-2012-4207)

A flaw was found in the location object implementation in Thunderbird.
Malicious content could possibly use this flaw to allow restricted
content to be loaded by plug-ins. (CVE-2012-4209)

A flaw was found in the way cross-origin wrappers were implemented.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-5841)

A flaw was found in the evalInSandbox implementation in Thunderbird.
Malicious content could use this flaw to perform cross-site scripting
attacks. (CVE-2012-4201)

Red Hat would like to thank the Mozilla project for reporting these
issues. Upstream acknowledges Abhishek Arya, miaubiz, Jesse Ruderman,
Andrew McCreight, Bob Clary, Kyle Huey, Atte Kettunen, Masato
Kinugawa, Mariusz Mlynski, Bobby Holley, and moz_bug_r_a4 as the
original reporters of these issues.

Note: All issues except CVE-2012-4202 cannot be exploited by a
specially crafted HTML mail message as JavaScript is disabled by
default for mail messages. They could be exploited another way in
Thunderbird, for example, when viewing the full remote content of an
RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.11 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-November/003144.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:thunderbird");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"thunderbird-10.0.11-1.0.1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
