#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51636);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2013/10/25 23:56:05 $");

  script_cve_id("CVE-2010-1166", "CVE-2010-2240");

  script_name(english:"SuSE 11.1 Security Update : Xorg (SAT Patch Number 2968)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The X.Org X11 Server was updated to fix several bugs and 2 security
issues :

  - This fix adds a workaround for overlapping stacks and
    heaps in case of OOM conditions.This workaround is
    necessary if the kernel is not properly adding guard or
    gap-pages below the stack. (CVE-2010-2240)

  - The fbComposite function in fbpict.c in the Render
    extension in the X server in X.Org X11R7.1 allows remote
    authenticated users to cause a denial of service (memory
    corruption and daemon crash) or possibly execute
    arbitrary code via a crafted request, related to an
    incorrect macro definition. (CVE-2010-1166)

Non-Security Bugs fixed :

  - Fix some shortcomings in the Xdmcp implementation. It
    used to suppress loopback addresses from the list of
    potential display addresses to report to xdm, even when
    talking to xdm through a loopback address. Now only
    display addresses of the same kind as the xdm connection
    are reported to xdm.

  - This most notably helps Xvnc servers contacting the
    local xdm, because they were severely affected by the
    suppression of"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=462283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=597232"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=605191"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=618152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=625598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-1166.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-2240.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 2968.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)11") audit(AUDIT_OS_NOT, "SuSE 11");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 11", cpu);

pl = get_kb_item("Host/SuSE/patchlevel");
if (isnull(pl) || int(pl) != 1) audit(AUDIT_OS_NOT, "SuSE 11.1");


flag = 0;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-Xvnc-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-server-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"xorg-x11-server-extra-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-Xvnc-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-server-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLED11", sp:1, cpu:"x86_64", reference:"xorg-x11-server-extra-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-Xvnc-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-server-7.4-27.24.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, reference:"xorg-x11-server-extra-7.4-27.24.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
