#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-9679.
#

include("compat.inc");

if (description)
{
  script_id(77481);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/10/19 22:49:03 $");

  script_cve_id("CVE-2012-1571", "CVE-2014-2497", "CVE-2014-3587", "CVE-2014-5120");
  script_bugtraq_id(52225, 66233, 69325, 69375);
  script_xref(name:"FEDORA", value:"2014-9679");

  script_name(english:"Fedora 19 : php-5.5.16-1.fc19 (2014-9679)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"21 Aug 2014, PHP 5.5.16

Core :

  - Fixed bug #67693 (incorrect push to the empty array)
    (Tjerk)

    - Fixed bug #67717 (segfault in dns_get_record).
      (CVE-2014-3597) (Remi)

COM :

  - Fixed missing type checks in com_event_sink (Yussuf
    Khalil, Stas).

Fileinfo :

  - Fixed bug #67705 (extensive backtracking in rule regular
    expression). (CVE-2014-3538) (Remi)

    - Fixed bug #67716 (Segfault in cdf.c). (CVE-2014-3587)
      (Remi)

FPM :

  - Fixed bug #67635 (php links to systemd libraries without
    using pkg-config). (pacho at gentoo.org, Remi)

GD :

  - Fixed bug #66901 (php-gd 'c_color' NULL pointer
    dereference). (CVE-2014-2497) (Remi)

    - Fixed bug #67730 (Null byte injection possible with
      imagexxx functions). (CVE-2014-5120) (Ryan Mauger)

Milter :

  - Fixed bug #67715 (php-milter does not build and crashes
    randomly). (Mike) OpenSSL :

  - Fixed missing type checks in OpenSSL options (Yussuf
    Khalil, Stas).

readline :

  - Fixed bug #55496 (Interactive mode doesn't force a
    newline before the prompt). (Bob, Johannes)

    - Fixed bug #67496 (Save command history when exiting
      interactive shell with control-c). (Dmitry Saprykin,
      Johannes)

Sessions :

  - Fixed missing type checks in php_session_create_id
    (Yussuf Khalil, Stas).

ODBC :

  - Fixed bug #60616 (odbc_fetch_into returns junk data at
    end of multi-byte char fields). (Keyur)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1076676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1128587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1132793"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-September/137247.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3f2dd6d9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:19");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^19([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 19.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC19", reference:"php-5.5.16-1.fc19")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
