#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-1751.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(81360);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 23:06:16 $");

  script_cve_id("CVE-2015-0211", "CVE-2015-0212", "CVE-2015-0213", "CVE-2015-0214", "CVE-2015-0215", "CVE-2015-0216", "CVE-2015-0217", "CVE-2015-0218");
  script_xref(name:"FEDORA", value:"2015-1751");

  script_name(english:"Fedora 21 : moodle-2.7.5-1.fc21 (2015-1751)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following security notifications have now been made public :

======================================================================
======== MSA-15-0001: Insufficient access check in LTI module

Description: Absence of capability check in AJAX backend script could
allow any enrolled user to search the list of registered tools Issue
summary: mod/lti/ajax.php security problems Severity/Risk: Minor
Versions affected: 2.8 to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and
earlier unsupported versions Versions fixed: 2.8.2, 2.7.4 and 2.6.7
Reported by: Petr Skoda Issue no.: MDL-47920 CVE identifier:
CVE-2015-0211 Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
47920

======================================================================
======== MSA-15-0002: XSS vulnerability in course request pending
approval page

Description: Course summary on course request pending approval page
was displayed to the manager unescaped and could be used for XSS
attack Issue summary: XSS in course request pending approval page
(Privilege Escalation?) Severity/Risk: Serious Versions affected: 2.8
to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and earlier unsupported versions
Versions fixed: 2.8.2, 2.7.4 and 2.6.7 Reported by: Skylar Kelty Issue
no.: MDL-48368 Workaround: Grant permission moodle/course:request only
to trusted users CVE identifier: CVE-2015-0212 Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48368

======================================================================
======== MSA-15-0003: CSRF possible in Glossary module

Description: Two files in the Glossary module lacked a session key
check potentially allowing cross-site request forgery Issue summary:
Multiple CSRF in mod glossary Severity/Risk: Serious Versions
affected: 2.8 to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and earlier
unsupported versions Versions fixed: 2.8.2, 2.7.4 and 2.6.7 Reported
by: Ankit Agarwal Issue no.: MDL-48106 CVE identifier: CVE-2015-0213
Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48106

======================================================================
======== MSA-15-0004: Information leak through messaging functions in
web-services

Description: Through web-services it was possible to access
messaging-related functions such as people search even if messaging is
disabled on the site Issue summary: Messages external functions
doesn't check if messaging is enabled Severity/Risk: Minor Versions
affected: 2.8 to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and earlier
unsupported versions Versions fixed: 2.8.2, 2.7.4 and 2.6.7 Reported
by: Juan Leyva Issue no.: MDL-48329 Workaround: Disable web services
or disable individual message-related functions CVE identifier:
CVE-2015-0214 Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48329

======================================================================
======== MSA-15-0005: Insufficient access check in calendar functions
in web-services

Description: Through web-services it was possible to get information
about calendar events which user did not have enough permissions to
see Issue summary: calendar/externallib.php lacks
self::validate_context($context); Severity/Risk: Minor Versions
affected: 2.8 to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and earlier
unsupported versions Versions fixed: 2.8.2, 2.7.4 and 2.6.7 Reported
by: Petr Skoda Issue no.: MDL-48017 CVE identifier: CVE-2015-0215
Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48017

======================================================================
======== MSA-15-0006: Capability to grade Lesson module is missing XSS
bitmask

Description: Users with capability to grade in Lesson module were not
reported as users with XSS risk but their feedback was displayed
without cleaning Issue summary: mod/lesson:grade capability missing
RISK_XSS but essay feedback is displayed with noclean=true
Severity/Risk: Minor Versions affected: 2.8 to 2.8.1 Versions fixed:
2.8.2 Reported by: Damyon Wiese Issue no.: MDL-48034 CVE identifier:
CVE-2015-0216 Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48034

======================================================================
======== MSA-15-0007: ReDoS possible in the multimedia filter

Description: Not optimal regular expression in the filter could be
exploited to create extra server load or make particular page
unavailable Issue summary: ReDOS in the multimedia filter
Severity/Risk: Serious Versions affected: 2.8 to 2.8.1, 2.7 to 2.7.3,
2.6 to 2.6.6 and earlier unsupported versions Versions fixed: 2.8.2,
2.7.4 and 2.6.7 Reported by: Nicolas Martignoni Issue no.: MDL-48546
Workaround: Disable multimedia filter CVE identifier: CVE-2015-0217
Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
48546

======================================================================
======== MSA-15-0008: Forced logout through Shibboleth authentication
plugin

Description: It was possible to forge a request to logout users even
when not authenticated through Shibboleth Issue summary: Forced logout
via auth/shibboleth/logout.php Severity/Risk: Serious Versions
affected: 2.8 to 2.8.1, 2.7 to 2.7.3, 2.6 to 2.6.6 and earlier
unsupported versions Versions fixed: 2.8.2, 2.7.4 and 2.6.7 Reported
by: Petr Skoda Issue no.: MDL-47964 Workaround: Deny access to file
auth/shibboleth/logout.php in webserver configuration CVE identifier:
CVE-2015-0218 Changes (master):
http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-
47964

======================================================================
========

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-47920
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?727765b3"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-47964
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc5a7611"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48017
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?864d680d"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48034
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fc0ccea3"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48106
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0290e85a"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48329
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ff3fbb8"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48368
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7368900b"
  );
  # http://git.moodle.org/gw?p=moodle.git&a=search&h=HEAD&st=commit&s=MDL-48546
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c3fa9023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1183694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1183695"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-February/149920.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e7699242"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected moodle package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"moodle-2.7.5-1.fc21")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "moodle");
}
