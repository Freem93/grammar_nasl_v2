#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-d9d620366e.
#

include("compat.inc");

if (description)
{
  script_id(99614);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_xref(name:"FEDORA", value:"2017-d9d620366e");

  script_name(english:"Fedora 24 : php-pear-CAS (2017-d9d620366e)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Changes in version 1.3.5**

  - Security Fixes :

  - Fix possible authentication bypass in validateCAS20
    [#228] (Gregory Boddin)

  - Bug Fixes :

  - Fix file permissions (non-executable) [#177] (Remi
    Collet)

  - Fixed translations Greek and Japanese [#192] (ikari7789)

  - Fix errors under phpdbg [#204] (MasonM)

  - Fix logout replication error [#213] (Gregory Boddin)

  - Improvement :

  - Add more debug info to logout code [#95] (Joachim
    Fritschi)

  - Allow longer ticket >32 chars for PGTStorage [#130]
    (Joachim Fritchi)

  - Improved verification of supplied CA arguments [#172]
    (Joachim Fritschi)

  - Change minimum supported php version to 5.4 in
    documentation (Joachim Fritschi)

  - Add message to CAS_Authentication_Exception [#197]
    (Baldinof)

  - Ingnore composer related files and directories [#201]
    (greg0ire)

  - Add setter for cas client [#206] (greg0ire)

  - Add callback for attribute parsing [#205] (Gregory
    Boddin)

  - Added setter for base url [#208] (LeopardDennis)

  - Fix documentation of code documentation [#216] (erozqba)

  - Improved https detection by HTTP_X_FORWARDED_Protocol
    [#220] (Gregory Boddin)

  - Add language support for simplified chinese [#227]
    (phy25)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-d9d620366e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-pear-CAS package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pear-CAS");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:24");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^24([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 24", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC24", reference:"php-pear-CAS-1.3.5-1.fc24")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-pear-CAS");
}
