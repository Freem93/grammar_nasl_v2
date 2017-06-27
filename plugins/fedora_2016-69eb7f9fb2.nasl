#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-69eb7f9fb2.
#

include("compat.inc");

if (description)
{
  script_id(90813);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2017/02/15 14:34:00 $");

  script_cve_id("CVE-2015-2181", "CVE-2015-8864", "CVE-2016-4068", "CVE-2016-4069");
  script_xref(name:"FEDORA", value:"2016-69eb7f9fb2");

  script_name(english:"Fedora 23 : roundcubemail-1.1.5-1.fc23 (2016-69eb7f9fb2)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Release 1.1.5** * Plugin API: Added html2text hook * Plugin API:
Added addressbook_export hook * Fix missing emoticons on html-to-text
conversion * Fix random 'access to this resource is secured against
CSRF' message at logout (#4956) * Fix missing language name in 'Add to
Dictionary' request in HTML mode (#4951) * Enable use of TLSv1.1 and
TLSv1.2 for IMAP (#4955) * Fix XSS issue in SVG images handling
(#4949) * Fix (again) security issue in DBMail driver of password
plugin (CVE-2015-2181) (#4958) * Fix bug in long recipients list
parsing for cases where recipient name contained @-char (#4964)

  - Fix additional_message_headers plugin compatibility with
    Mail_Mime >= 1.9 (#4966) * Hide DSN option in
    Preferences when smtp_server is not used (#4967)

  - Protect download urls against CSRF using unique request
    tokens (#4957) * newmail_notifier Plugin: Refactored
    desktop notifications * Fix so contactlist_fields option
    can be set via config file * Fix so SPECIAL-USE
    assignments are forced only until user sets special
    folders (#4782) * Fix performance in reverting order of
    THREAD result * Fix converting mail addresses with www.
    into mailto links (#5197)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1330084"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-April/183288.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97b0d408"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected roundcubemail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:roundcubemail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"roundcubemail-1.1.5-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "roundcubemail");
}
