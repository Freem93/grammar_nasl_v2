#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-11649.
#

include("compat.inc");

if (description)
{
  script_id(67317);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/10/19 21:02:57 $");

  script_cve_id("CVE-2013-2173", "CVE-2013-2199", "CVE-2013-2200", "CVE-2013-2201", "CVE-2013-2202", "CVE-2013-2203", "CVE-2013-2204", "CVE-2013-2205");
  script_xref(name:"FEDORA", value:"2013-11649");

  script_name(english:"Fedora 17 : wordpress-3.5.2-1.fc17 (2013-11649)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"WordPress 3.5.2 is now available. This is the second maintenance
release of 3.5, fixing 12 bugs. This is a security release for all
previous versions and we strongly encourage you to update your sites
immediately. The WordPress security team resolved seven security
issues, and this release also contains some additional security
hardening.

The security fixes included :

  - Blocking server-side request forgery attacks, which
    could potentially enable an attacker to gain access to a
    site.

    - Disallow contributors from improperly publishing
      posts, reported by Konstantin Kovshenin, or
      reassigning the post's authorship, reported by Luke
      Bryan.

    - An update to the SWFUpload external library to fix
      cross-site scripting vulnerabilities. Reported by mala
      and Szymon Gruszecki. (Developers: More on SWFUpload
      here.)

    - Prevention of a denial of service attack, affecting
      sites using password-protected posts.

    - An update to an external TinyMCE library to fix a
      cross-site scripting vulnerability. Reported by Wan
      Ikram.

    - Multiple fixes for cross-site scripting. Reported by
      Andrea Santese and Rodrigo.

    - Avoid disclosing a full file path when a upload fails.
      Reported by Jakub Galczyk.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=973254"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=976784"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-July/110566.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f6740c18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected wordpress package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"wordpress-3.5.2-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wordpress");
}
