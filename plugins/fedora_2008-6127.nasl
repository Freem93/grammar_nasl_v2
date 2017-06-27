#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-6127.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(33416);
  script_version ("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/12/08 20:21:53 $");

  script_cve_id("CVE-2008-2798", "CVE-2008-2799", "CVE-2008-2800", "CVE-2008-2801", "CVE-2008-2802", "CVE-2008-2803", "CVE-2008-2805", "CVE-2008-2807", "CVE-2008-2808", "CVE-2008-2809", "CVE-2008-2810", "CVE-2008-2811");
  script_bugtraq_id(30038);
  script_xref(name:"FEDORA", value:"2008-6127");

  script_name(english:"Fedora 8 : Miro-1.2.3-2.fc8 / blam-1.8.3-16.fc8 / chmsee-1.0.0-2.31.fc8 / devhelp-0.16.1-8.fc8 / etc (2008-6127)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated firefox packages that fix several security issues are now
available for Fedora 8. This update has been rated as having critical
security impact by the Fedora Security Response Team. Multiple flaws
were found in the processing of malformed JavaScript content. A web
page containing such malicious content could cause Firefox to crash
or, potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-2801, CVE-2008-2802, CVE-2008-2803) Several flaws were found
in the processing of malformed web content. A web page containing
malicious content could cause Firefox to crash or, potentially,
execute arbitrary code as the user running Firefox. (CVE-2008-2798,
CVE-2008-2799, CVE-2008-2811) Several flaws were found in the way
malformed web content was displayed. A web page containing specially
crafted content could potentially trick a Firefox user into
surrendering sensitive information. (CVE-2008-2800) Two local file
disclosure flaws were found in Firefox. A web page containing
malicious content could cause Firefox to reveal the contents of a
local file to a remote attacker. (CVE-2008-2805, CVE-2008-2810) A flaw
was found in the way a malformed .properties file was processed by
Firefox. A malicious extension could read uninitialized memory,
possibly leaking sensitive data to the extension. (CVE-2008-2807) A
flaw was found in the way Firefox escaped a listing of local file
names. If a user could be tricked into listing a local directory
containing malicious file names, arbitrary JavaScript could be run
with the permissions of the user running Firefox. (CVE-2008-2808) A
flaw was found in the way Firefox displayed information about
self-signed certificates. It was possible for a self-signed
certificate to contain multiple alternate name entries, which were not
all displayed to the user, allowing them to mistakenly extend trust to
an unknown site. (CVE-2008-2809) Updated packages update Mozilla
Firefox to upstream version 2.0.0.15 to address these flaws:
http://www.mozilla.org/projects/security/known-
vulnerabilities.html#firefox2.0.0.15 This update also contains blam,
chmsee, devhelp, epiphany, epiphany-extensions, galeon,
gnome-python2-extras, gnome-web- photo, gtkmozembedmm, kazehakase,
liferea, Miro, openvrml, ruby-gnome2 and yelp packages rebuilt against
new Firefox / Gecko libraries.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/projects/security/known-"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452709"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452710"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452711"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=452712"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=453007"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012075.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2460e57"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012076.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3b4c17f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012077.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ff5cbb0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012078.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4d06816c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012079.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e60763df"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012080.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa203d27"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012081.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?18c78a76"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012082.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?624121d5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012083.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8769e8c5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012084.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?379c4555"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012085.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?168014e0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012086.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7feff463"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012087.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e44ead7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012088.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f0dc44e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012089.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4ee7d0be"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-July/012091.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2a6fefa4"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 200, 264, 287, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");
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
if (rpm_check(release:"FC8", reference:"Miro-1.2.3-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"blam-1.8.3-16.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"chmsee-1.0.0-2.31.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"devhelp-0.16.1-8.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-2.20.3-5.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"epiphany-extensions-2.20.1-8.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"firefox-2.0.0.15-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"galeon-2.0.4-3.fc8.3")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-python2-extras-2.19.1-15.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gnome-web-photo-0.3-11.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"gtkmozembedmm-1.4.2.cvs20060817-21.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"kazehakase-0.5.4-2.fc8.2")) flag++;
if (rpm_check(release:"FC8", reference:"liferea-1.4.15-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"openvrml-0.17.6-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"ruby-gnome2-0.17.0-0.2.rc1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"yelp-2.20.0-10.fc8")) flag++;


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
