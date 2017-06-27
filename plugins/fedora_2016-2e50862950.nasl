#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2016-2e50862950.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(94024);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/10/25 16:58:35 $");

  script_cve_id("CVE-2016-5147", "CVE-2016-5148", "CVE-2016-5149", "CVE-2016-5150", "CVE-2016-5151", "CVE-2016-5152", "CVE-2016-5153", "CVE-2016-5154", "CVE-2016-5155", "CVE-2016-5156", "CVE-2016-5157", "CVE-2016-5158", "CVE-2016-5159", "CVE-2016-5160", "CVE-2016-5161", "CVE-2016-5162", "CVE-2016-5163", "CVE-2016-5164", "CVE-2016-5165", "CVE-2016-5166", "CVE-2016-5167", "CVE-2016-5170", "CVE-2016-5171", "CVE-2016-5172", "CVE-2016-5173", "CVE-2016-5174", "CVE-2016-5175", "CVE-2016-5177", "CVE-2016-5178");
  script_xref(name:"FEDORA", value:"2016-2e50862950");

  script_name(english:"Fedora 23 : chromium (2016-2e50862950)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2016-5177, CVE-2016-5178

https://googlechromereleases.blogspot.com/2016/09/stable-channel-updat
e-for-desktop_29.html

----

Update to 53.0.2785.116.

https://chromium.googlesource.com/chromium/src/+log/53.0.2785.113..53.
0.2785.116?pretty=fuller&n=10000

----

Update to 53.0.2785.113

Security fix for CVE-2016-5170, CVE-2016-5171, CVE-2016-5172,
CVE-2016-5173, CVE-2016-5174, CVE-2016-5175

----

Stable update to 53.0.2785.101.

Security fix for CVE-2016-5147, CVE-2016-5148, CVE-2016-5149,
CVE-2016-5150, CVE-2016-5151, CVE-2016-5152, CVE-2016-5153,
CVE-2016-5154, CVE-2016-5155, CVE-2016-5156, CVE-2016-5157,
CVE-2016-5158, CVE-2016-5159, CVE-2016-5161, CVE-2016-5162,
CVE-2016-5163, CVE-2016-5164, CVE-2016-5165, CVE-2016-5166,
CVE-2016-5160, CVE-2016-5167

Also applies fix for chrome-remote-desktop where HOME env variable was
not properly set via systemd service.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2016-2e50862950"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected chromium package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:chromium");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC23", reference:"chromium-53.0.2785.143-1.fc23")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "chromium");
}
