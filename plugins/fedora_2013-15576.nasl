#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2013-15576.
#

include("compat.inc");

if (description)
{
  script_id(69821);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/10/19 21:12:42 $");

  script_cve_id("CVE-2013-1438", "CVE-2013-1439");
  script_bugtraq_id(62057, 62060);
  script_xref(name:"FEDORA", value:"2013-15576");

  script_name(english:"Fedora 18 : LibRaw-0.14.8-3.fc18.20120830git98d925 (2013-15576)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Raphael Geissert reported two denial of service flaws in LibRaw [1] :

CVE-2013-1438 :

Specially crafted photo files may trigger a division by zero, an
infinite loop, or a NULL pointer dereference in libraw leading to
denial of service in applications using the library. These
vulnerabilities appear to originate in dcraw and as such any program
or library based on it is affected. To name a few confirmed
applications: dcraw, ufraw. Other affected software: shotwell,
darktable, and libkdcraw (Qt-style interface to libraw, using embedded
copy) which is used by digikam.

Google Picasa apparently uses dcraw/ufraw so it might be affected.
dcraw's homepage has a list of applications that possibly still use
it: http://cybercom.net/~dcoffin/dcraw/

Affected versions of libraw: confirmed: 0.8-0.15.3; but it is likely
that all versions are affected.

Fixed in: libraw 0.15.4

CVE-2013-1439 :

Specially crafted photo files may trigger a series of conditions in
which a NULL pointer is dereferenced leading to denial of service in
applications using the library. These three vulnerabilities are
in/related to the 'faster LJPEG decoder', which upstream states was
introduced in LibRaw 0.13 and support for which is going to be dropped
in 0.16.

Affected versions of libraw: 0.13.x-0.15.x

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://cybercom.net/~dcoffin/dcraw/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1002717"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2013-September/115414.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?50da6143"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected LibRaw package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:LibRaw");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/10");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"LibRaw-0.14.8-3.fc18.20120830git98d925")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "LibRaw");
}
