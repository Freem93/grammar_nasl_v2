#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1435.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31060);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_xref(name:"FEDORA", value:"2008-1435");

  script_name(english:"Fedora 7 : Miro-1.1-3.fc7 / chmsee-1.0.0-1.28.fc7 / devhelp-0.13-13.fc7 / epiphany-2.18.3-6.fc7 / etc (2008-1435)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. Several flaws were
found in the way Firefox processed certain malformed web content. A
web page containing malicious content could cause Firefox to crash, or
potentially execute arbitrary code as the user running Firefox.
(CVE-2008-0412, CVE-2008-0413, CVE-2008-0415, CVE-2008-0419) Several
flaws were found in the way Firefox displayed malformed web content. A
web page containing specially crafted content could trick a user into
surrendering sensitive information. (CVE-2008-0591, CVE-2008-0593) A
flaw was found in the way Firefox stored password data. If a user
saves login information for a malicious website, it could be possible
to corrupt the password database, preventing the user from properly
accessing saved password data. (CVE-2008-0417) A flaw was found in the
way Firefox handles certain chrome URLs. If a user has certain
extensions installed, it could allow a malicious website to steal
sensitive session data. Note: this flaw does not affect a default
installation of Firefox. (CVE-2008-0418) A flaw was found in the way
Firefox saves certain text files. If a website offers a file of type
'plain/text', rather than 'text/plain', Firefox will not show future
'text/plain' content to the user in the browser, forcing them to save
those files locally to view the content. (CVE-2008-0592) Users of
firefox are advised to upgrade to these updated packages, which
contain updated packages to resolve these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431751"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431752"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431756"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=432040"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007653.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?63627475"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4225307a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007655.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f2dbb08"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007656.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ded22244"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f7f870dd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007658.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a24c3429"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007659.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3bc6d673"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007660.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d6e3b3b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007661.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e9ddf257"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007662.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?382378d6"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007663.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86d0cc5c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007664.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8fa9b38c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007665.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d5c6865"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007666.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6df462e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"Miro-1.1-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"chmsee-1.0.0-1.28.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-0.13-13.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-2.18.3-6.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-extensions-2.18.3-7")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.12-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"galeon-2.0.3-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-extras-2.14.3-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-1.4.2.cvs20060817-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-0.5.2-1.fc7.2")) flag++;
if (rpm_check(release:"FC7", reference:"liferea-1.4.9-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-0.16.7-3.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-0.16.0-21.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"yelp-2.18.1-9.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / chmsee / devhelp / epiphany / epiphany-extensions / firefox / etc");
}
