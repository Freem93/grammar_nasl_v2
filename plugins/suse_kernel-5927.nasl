#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59135);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/22 20:32:47 $");

  script_cve_id("CVE-2008-4933", "CVE-2008-5025", "CVE-2008-5029", "CVE-2008-5079", "CVE-2008-5182");

  script_name(english:"SuSE 10 Security Update : Linux kernel (ZYPP Patch Number 5927)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SUSE Linux Enterprise 10 Service Pack 2 kernel was updated to fix
some security issues and various bugs.

The following security problems have been fixed :

  - net/atm/svc.c in the ATM subsystem allowed local users
    to cause a denial of service (kernel infinite loop) by
    making two calls to svc_listen for the same socket, and
    then reading a /proc/net/atm/ *vc file, related to
    corruption of the vcc table. (CVE-2008-5079)

  - The __scm_destroy function in net/core/scm.c makes
    indirect recursive calls to itself through calls to the
    fput function, which allows local users to cause a
    denial of service (panic) via vectors related to sending
    an SCM_RIGHTS message through a UNIX domain socket and
    closing file descriptors. (CVE-2008-5029)

  - Buffer overflow in the hfsplus_find_cat function in
    fs/hfsplus/catalog.c allowed attackers to cause a denial
    of service (memory corruption or system crash) via an
    hfsplus filesystem image with an invalid catalog
    namelength field, related to the
    hfsplus_cat_build_key_uni function. (CVE-2008-4933)

  - Stack-based buffer overflow in the hfs_cat_find_brec
    function in fs/hfs/catalog.c allowed attackers to cause
    a denial of service (memory corruption or system crash)
    via an hfs filesystem image with an invalid catalog
    namelength field, a related issue to CVE-2008-4933.
    (CVE-2008-5025)

  - The inotify functionality might allow local users to
    gain privileges via unknown vectors related to race
    conditions in inotify watch removal and umount.
    (CVE-2008-5182)

A lot of other bugs were fixed, a detailed list can be found in the
RPM changelog."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-4933.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5029.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5079.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-5182.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 5927.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(119, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLED10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-debug-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-default-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-kdump-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-smp-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-source-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-syms-2.6.16.60-0.34")) flag++;
if (rpm_check(release:"SLES10", sp:2, cpu:"x86_64", reference:"kernel-xen-2.6.16.60-0.34")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
