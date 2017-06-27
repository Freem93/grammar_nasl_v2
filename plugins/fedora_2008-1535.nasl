#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1535.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31067);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-0412", "CVE-2008-0413", "CVE-2008-0414", "CVE-2008-0415", "CVE-2008-0417", "CVE-2008-0418", "CVE-2008-0419", "CVE-2008-0591", "CVE-2008-0592", "CVE-2008-0593", "CVE-2008-0594");
  script_xref(name:"FEDORA", value:"2008-1535");

  script_name(english:"Fedora 8 : Miro-1.1-3.fc8 / blam-1.8.3-13.fc8 / chmsee-1.0.0-1.28.fc8 / devhelp-0.16.1-5.fc8 / etc (2008-1535)");
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
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?150b6c21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007755.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b751fe08"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007756.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8bd9950"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007757.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d571352f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007758.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?df5f34ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007759.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?080b7023"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007760.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1bc21d1f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007761.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb3ac43d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007762.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?406b01bc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007763.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe5d5ec2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007764.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d0528e90"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007765.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4dd87a98"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007766.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dbdbc11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007767.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?67a56ae1"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007768.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?11b25edd"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007769.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?34ff5880"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 22, 79, 94, 200, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:Miro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:blam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chmsee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:epiphany-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:galeon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-python2-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-web-photo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:liferea");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openvrml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-gnome2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"Miro-1.1-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-13.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-1.28.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.2-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.12-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-1.fc8.2")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-12.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-8.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-18.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.2-1.fc8.2")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.11-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.5-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.16.0-20.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-7.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Miro / blam / chmsee / devhelp / epiphany / epiphany-extensions / etc");
}
