#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-3099.
#

include("compat.inc");

if (description)
{
  script_id(36041);
  script_version ("$Revision: 1.18 $");
  script_cvs_date("$Date: 2015/10/21 22:41:47 $");

  script_cve_id("CVE-2009-1044", "CVE-2009-1169");
  script_bugtraq_id(34181, 34235);
  script_xref(name:"FEDORA", value:"2009-3099");

  script_name(english:"Fedora 9 : Miro-2.0.3-2.fc9 / blam-1.8.5-7.fc9.1 / chmsee-1.0.1-10.fc9 / devhelp-0.19.1-10.fc9 / etc (2009-3099)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Firefox is an open source Web browser. XULRunner provides the
XUL Runtime environment for Mozilla Firefox. A memory corruption flaw
was discovered in the way Firefox handles XML files containing an XSLT
transform. A remote attacker could use this flaw to crash Firefox or,
potentially, execute arbitrary code as the user running Firefox.
(CVE-2009-1169) A flaw was discovered in the way Firefox handles
certain XUL garbage collection events. A remote attacker could use
this flaw to crash Firefox or, potentially, execute arbitrary code as
the user running Firefox. (CVE-2009-1044) This update also provides
depending packages rebuilt against new Firefox version. Miro updates
to upstream 2.0.3. Provides new features and fixes various bugs in
1.2.x series

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f9c1612"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021817.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b542ad2d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021818.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5d22176"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021819.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5c93b433"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021820.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57053757"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021821.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?39789ca2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021822.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9ba7b21"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021823.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a1e24b7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021824.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?415d08fa"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021825.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e324b372"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021826.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?72b77952"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021827.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fb476644"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021828.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?66395d66"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021829.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?508e9e80"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021830.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8f9e5fdc"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021831.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?283c9638"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021832.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bb2129f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021833.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ed31a681"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021853.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?17849551"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021854.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?92499e26"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021855.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7631ea4b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021856.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da6c76e7"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021857.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfd1e5e2"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021858.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?38790867"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021859.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f303152"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021860.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc18ed11"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021861.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?155eaa70"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021862.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bd569e79"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021863.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1092d36"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021864.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81530d6f"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021865.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?985bca7d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021866.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?88ae8ebb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021867.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a88b845"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021868.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?485482d3"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021869.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9d3c0ab"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-March/021870.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d01ed437"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(399);

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:google-gadgets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtkmozembedmm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kazehakase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mozvoikko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mugshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:totem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:yelp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"Miro-2.0.3-2.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"blam-1.8.5-7.fc9.1")) flag++;
if (rpm_check(release:"FC9", reference:"chmsee-1.0.1-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"devhelp-0.19.1-10.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-2.22.2-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"epiphany-extensions-2.22.1-9.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"firefox-3.0.8-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"galeon-2.0.7-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-python2-extras-2.19.1-25.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gnome-web-photo-0.3-19.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"google-gadgets-0.10.5-4.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gtkmozembedmm-1.4.2.cvs20060817-27.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"kazehakase-0.5.6-1.fc9.5")) flag++;
if (rpm_check(release:"FC9", reference:"mozvoikko-0.9.5-8.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"mugshot-1.2.2-7.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"totem-2.23.2-13.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"xulrunner-1.9.0.8-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"yelp-2.22.1-10.fc9")) flag++;


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
