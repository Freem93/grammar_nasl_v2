#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-8423.
#

include("compat.inc");

if (description)
{
  script_id(34314);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/10/21 22:23:17 $");

  script_cve_id("CVE-2008-4191");
  script_bugtraq_id(31241);
  script_xref(name:"FEDORA", value:"2008-8423");

  script_name(english:"Fedora 8 : emacspeak-28.0-3.fc8 (2008-8423)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Sep 26 2008 Jens Petersen <petersen at redhat.com> -
    28.0-3

    - (CVE-2008-4191) fix tmpfile vulnerability in
      extract-table.pl with emacspeak-28.0-tmpfile.patch
      from upstream svn (#463819)

  - Fri Sep 26 2008 Jens Petersen <petersen at redhat.com> -
    28.0-2

    - fix broken generated deps reported by mtasaka
      (#463899)

    - script the replacement of tcl with tclsh to fix
      missing dtk-soft

    - replace python2.4 with python in HTTPSpeaker.py

    - Thu Sep 25 2008 Jens Petersen <petersen at redhat.com>
      - 28.0-1

    - update to 28.0 with emacspeak-28.0-no-httpd.patch

    - replace emacspeak-tcl-pkgreq-tclx.patch with sed

    - emacspeak-no-linux-espeak.patch no longer needed

    - update emacspeak-15.0-fixpref.patch for patch fuzz

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=463819"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-October/014952.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d5eb3c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected emacspeak package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:emacspeak");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC8", reference:"emacspeak-28.0-3.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "emacspeak");
}
