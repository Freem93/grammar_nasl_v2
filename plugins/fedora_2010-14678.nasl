#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-14678.
#

include("compat.inc");

if (description)
{
  script_id(49248);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/11 13:16:09 $");

  script_cve_id("CVE-2010-0787", "CVE-2010-3069");
  script_bugtraq_id(43212);
  script_osvdb_id(67994);
  script_xref(name:"FEDORA", value:"2010-14678");

  script_name(english:"Fedora 12 : samba-3.4.9-60.fc12 (2010-14678)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Sep 9 2010 Guenther Deschner <gdeschner at
    redhat.com> - 3.4.9-60

    - Security Release, fixes CVE-2010-3069

    - resolves: #630869

    - Wed May 12 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.8-59

    - Update to 3.4.8

    - Make sure nmb and smb initscripts return LSB compliant
      return codes

    - resolves: #521095

    - Mon Mar 8 2010 Simo Sorce <ssorce at redhat.com> -
      3.4.7-58

    - Security update to 3.4.7

    - Fixes CVE-2010-0728

    - Wed Feb 24 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.6-57

    - Update to 3.4.6

    - Wed Feb 17 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.5-56

    - Fix crash in cifs.upcall

    - resolves: #565446

    - Tue Jan 26 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.5-55

    - Security Release, fixes CVE-2009-3297

    - resolves: #532940

    - Tue Jan 26 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.5-54

    - Fix crash in pdbedit

    - resolves: #541267

    - Tue Jan 19 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.5-53

    - Update to 3.4.5

    - Thu Jan 14 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.4-52

    - Fix crash bug in libsmbclient (SMBC_parse_path)

    - resolves: #552658

    - Thu Jan 7 2010 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.4-51

    - Update to 3.4.4

    - Tue Dec 1 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.3-50

    - Fix uninitialized rpc client pipe, causing winbind to
      crash

    - resolves: #541328

    - Wed Nov 25 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.3-49

    - Various updates to inline documentation in default
      smb.conf file

    - resolves: #483703

    - Thu Oct 29 2009 Guenther Deschner <gdeschner at
      redhat.com> - 3.4.3-48

    - Update to 3.4.3

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=630869"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-September/047697.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3c0e8cfc"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected samba package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"samba-3.4.9-60.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
