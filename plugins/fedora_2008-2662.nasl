#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-2662.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(31689);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/08 20:11:36 $");

  script_cve_id("CVE-2008-1233", "CVE-2008-1234", "CVE-2008-1235", "CVE-2008-1236", "CVE-2008-1237", "CVE-2008-1238", "CVE-2008-1241");
  script_bugtraq_id(28448);
  script_xref(name:"FEDORA", value:"2008-2662");

  script_name(english:"Fedora 7 : Miro-1.1.2-2.fc7 / chmsee-1.0.0-1.30.fc7 / devhelp-0.13-15.fc7 / epiphany-2.18.3-8.fc7 / etc (2008-2662)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. Several flaws were
found in the processing of some malformed web content. A web page
containing such malicious content could cause Firefox to crash or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2008-1233, CVE-2008-1235, CVE-2008-1236, CVE-2008-1237) Several
flaws were found in the display of malformed web content. A web page
containing specially crafted content could, potentially, trick a
Firefox user into surrendering sensitive information. (CVE-2008-1234,
CVE-2008-1238, CVE-2008-1241) All Firefox users should upgrade to
these updated packages, which correct these issues, and are rebuilt
against the update Firefox packages.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438717"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438718"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=438730"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008891.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a60985bb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008892.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e698c52e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a347b664"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008894.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1a11951d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008895.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e659ac4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008896.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fef4a278"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008897.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa8742b5"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008898.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?907312be"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008899.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a43e3f49"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008900.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?afdb0626"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008901.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ef43dad0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008902.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?30c744a4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008903.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4afe99c2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008904.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?9269017c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79, 94, 287, 399);

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

  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/28");
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
if (rpm_check(release:"FC7", reference:"Miro-1.1.2-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"chmsee-1.0.0-1.30.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"devhelp-0.13-15.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-2.18.3-8.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"epiphany-extensions-2.18.3-8")) flag++;
if (rpm_check(release:"FC7", reference:"firefox-2.0.0.13-1.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"galeon-2.0.3-16.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gnome-python2-extras-2.14.3-9.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"gtkmozembedmm-1.4.2.cvs20060817-16.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"kazehakase-0.5.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"liferea-1.4.13-2.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"openvrml-0.16.7-4.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ruby-gnome2-0.16.0-22.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"yelp-2.18.1-10.fc7")) flag++;


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
