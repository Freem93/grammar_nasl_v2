#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34331);
  script_version ("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2008-0598", "CVE-2008-1673", "CVE-2008-2812", "CVE-2008-2931", "CVE-2008-3272", "CVE-2008-3275", "CVE-2008-3525");

  script_name(english:"SuSE 10 Security Update : the Linux Kernel (x86) (ZYPP Patch Number 5566)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the SUSE Linux Enterprise 10 Service Pack 1 kernel
contains lots of bugfixes and several security fixes :

  - Added missing capability checks in sbni_ioctl().
    (CVE-2008-3525)

  - On AMD64 some string operations could leak kernel
    information into userspace. (CVE-2008-0598)

  - Added range checking in ASN.1 handling for the CIFS and
    SNMP NAT netfilter modules. (CVE-2008-1673)

  - Fixed range checking in the snd_seq OSS ioctl, which
    could be used to leak information from the kernel.
    (CVE-2008-3272)

  - Fixed a memory leak when looking up deleted directories
    which could be used to run the system out of memory.
    (CVE-2008-3275)

  - The do_change_type function in fs/namespace.c did not
    verify that the caller has the CAP_SYS_ADMIN capability,
    which allows local users to gain privileges or cause a
    denial of service by modifying the properties of a
    mountpoint. (CVE-2008-2931)

  - Various NULL ptr checks have been added to tty op
    functions, which might have been used by local attackers
    to execute code. We think that this affects only devices
    openable by root, so the impact is limited.
    (CVE-2008-2812)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-0598.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1673.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2812.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-2931.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3272.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3275.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-3525.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5566.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119, 189, 200, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLED10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-bigsmp-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-debug-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-default-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-kdump-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-smp-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-source-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-syms-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xen-2.6.16.54-0.2.10")) flag++;
if (rpm_check(release:"SLES10", sp:1, cpu:"i586", reference:"kernel-xenpae-2.6.16.54-0.2.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
