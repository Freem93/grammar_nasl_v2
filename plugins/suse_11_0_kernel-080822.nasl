#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update kernel-171.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(40009);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:09:50 $");

  script_cve_id("CVE-2008-1673", "CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3276");

  script_name(english:"openSUSE Security Update : kernel (kernel-171)");
  script_summary(english:"Check for the kernel-171 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The openSUSE 11.0 kernel was updated to 2.6.25.16.

It fixes various stability bugs and also security bugs.

CVE-2008-1673: Fixed the range checking in the ASN.1 decoder in NAT
for SNMP and CIFS, which could have been used by a remote attacker to
crash the machine.

CVE-2008-3276: An integer overflow flaw was found in the Linux kernel
dccp_setsockopt_change() function. An attacker may leverage this
vulnerability to trigger a kernel panic on a victim's machine
remotely.

CVE-2008-3272: The snd_seq_oss_synth_make_info function in
sound/core/seq/oss/seq_oss_synth.c in the sound subsystem does not
verify that the device number is within the range defined by
max_synthdev before returning certain data to the caller, which allows
local users to obtain sensitive information.

CVE-2008-3275: The (1) real_lookup and (2) __lookup_hash functions in
fs/namei.c in the vfs implementation do not prevent creation of a
child dentry for a deleted (aka S_DEAD) directory, which allows local
users to cause a denial of service ('overflow' of the UBIFS orphan
area) via a series of attempted file creations within deleted
directories.

Also lots of bugs were fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=216857"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=374099"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=394667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=400815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=400874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=404892"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=406637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=407689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=408734"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=412823"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=415607"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=415690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=417505"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-pae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-vanilla");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE11\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.0", reference:"kernel-debug-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-default-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-pae-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-rt-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-rt_debug-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-source-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-syms-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-vanilla-2.6.25.16-0.1") ) flag++;
if ( rpm_check(release:"SUSE11.0", reference:"kernel-xen-2.6.25.16-0.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-debug / kernel-default / kernel-pae / kernel-rt / etc");
}
