#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-870.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(92309);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/07 20:46:54 $");

  script_cve_id("CVE-2016-4172", "CVE-2016-4173", "CVE-2016-4174", "CVE-2016-4175", "CVE-2016-4176", "CVE-2016-4177", "CVE-2016-4178", "CVE-2016-4179", "CVE-2016-4180", "CVE-2016-4181", "CVE-2016-4182", "CVE-2016-4183", "CVE-2016-4184", "CVE-2016-4185", "CVE-2016-4186", "CVE-2016-4187", "CVE-2016-4188", "CVE-2016-4189", "CVE-2016-4190", "CVE-2016-4217", "CVE-2016-4218", "CVE-2016-4219", "CVE-2016-4220", "CVE-2016-4221", "CVE-2016-4222", "CVE-2016-4223", "CVE-2016-4224", "CVE-2016-4225", "CVE-2016-4226", "CVE-2016-4227", "CVE-2016-4228", "CVE-2016-4229", "CVE-2016-4230", "CVE-2016-4231", "CVE-2016-4232", "CVE-2016-4233", "CVE-2016-4234", "CVE-2016-4235", "CVE-2016-4236", "CVE-2016-4237", "CVE-2016-4238", "CVE-2016-4239", "CVE-2016-4240", "CVE-2016-4241", "CVE-2016-4242", "CVE-2016-4243", "CVE-2016-4244", "CVE-2016-4245", "CVE-2016-4246", "CVE-2016-4247", "CVE-2016-4248", "CVE-2016-4249");

  script_name(english:"openSUSE Security Update : flash-player (openSUSE-2016-870)");
  script_summary(english:"Check for the openSUSE-2016-870 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Adobe Flash Player was updated to 11.2.202.632 to fix many security
issues tracked under the upstream advisory APSB16-25, allowing remote
attackers to execute arbitrary code when delivering specially crafted
Flash content. 

The following vulnerabilities were fixed :

  - CVE-2016-4172: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4173: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4174: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4175: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4176: stack corruption vulnerability that could
    lead to code execution

  - CVE-2016-4177: stack corruption vulnerability that could
    lead to code execution

  - CVE-2016-4178: security bypass vulnerability that could
    lead to information disclosure

  - CVE-2016-4179: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4180: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4181: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4182: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4183: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4184: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4185: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4186: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4187: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4188: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4189: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4190: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4217: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4218: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4219: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4220: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4221: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4222: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4223: type confusion vulnerability that could
    lead to code execution

  - CVE-2016-4224: type confusion vulnerability that could
    lead to code execution

  - CVE-2016-4225: type confusion vulnerability that could
    lead to code execution

  - CVE-2016-4226: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4227: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4228: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4229: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4230: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4231: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4232: memory leak vulnerability

  - CVE-2016-4233: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4234: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4235: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4236: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4237: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4238: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4239: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4240: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4241: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4242: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4243: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4244: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4245: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4246: memory corruption vulnerability that
    could lead to code execution

  - CVE-2016-4247: race condition vulnerability that could
    lead to information disclosure

  - CVE-2016-4248: use-after-free vulnerability that could
    lead to code execution

  - CVE-2016-4249: heap buffer overflow vulnerability that
    could lead to code execution"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988579"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected flash-player packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:flash-player-kde4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE13.1", reference:"flash-player-11.2.202.632-168.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-gnome-11.2.202.632-168.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"flash-player-kde4-11.2.202.632-168.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash-player / flash-player-gnome / flash-player-kde4");
}
