#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-1847.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(47276);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/08 20:31:53 $");

  script_cve_id("CVE-2009-2949", "CVE-2009-2950", "CVE-2009-3301", "CVE-2009-3302");
  script_bugtraq_id(38218);
  script_xref(name:"FEDORA", value:"2010-1847");

  script_name(english:"Fedora 12 : openoffice.org-3.1.1-19.26.fc12 (2010-1847)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Feb 12 2010 Caolan McNamara <caolanm at redhat.com>
    - 1:3.1.1-19.26

    - CVE-2009-2950 GIF file parsing heap overflow (caolanm)

    - CVE-2009-2949 integer overflow in XPM processing
      (caolanm)

    - CVE-2009-3301 .doc Table Parsing vulernability
      (caolanm)

    - CVE-2009-3302 .doc Table Parsing vulernability
      (caolanm)

    - Resolves: rhbz#561778
      openoffice.org-3.2.0.oooXXXXX.svx.safestyledelete.patc
      h

    - Resolves: rhbz#561989
      openoffice.org-3.2.0.ooo109009.sc.tooltipcrash.patch

    - Resolves: rhbz#445588 improve same name substitution

    - Tue Feb 2 2010 Caolan McNamara <caolanm at redhat.com>
      - 1:3.1.1-19.25

    - Resolves: rhbz#549890 add workspace.extmgr01.patch
      (dtardon)

    - Resolves: rhbz#551983 OpenOffice writer crashes when
      opening document with link in footnote (dtardon)

  - Resolves: rhbz#550316 Openoffice.org Impress loses
    graphics when background color is changed (dtardon)

  - Resolves: rhbz#554259 No autocorrect files for
    Lithuanian (dtardon)

    - Resolves: rhbz#553929 [abrt] crash in
      ColorConfigCtrl_Impl::ScrollHdl (dtardon)

  - Resolves: rhbz#549573 improve document compare (caolanm)

    - Resolves: rbhz#555257 openoffice cannot use JPEG
      images using CMYK colorspace (dtardon)

  - Resolves: rhbz#558342 [abrt] crash in
    SvxNumOptionsTabPage::InitControls (dtardon)

  - Resolves: ooo#108637/rhbz#558253 sfx2 uisavedir
    (caolanm)

    - Resolves: rhbz#560435 rtf dropcap crash (caolanm)

    - Resolves: rhbz#560996/rhbz#560353 qstartfixes
      (caolanm)

    - Tue Dec 22 2009 Caolan McNamara <caolanm at
      redhat.com> - 1:3.1.1-19.24

    - Resolves: rhbz#545824 bustage in writer with
      emboldened fonts

    - Fri Dec 18 2009 Caolan McNamara <caolanm at
      redhat.com> - 1:3.1.1-19.23

    - Resolves: rhbz#548512 workspace.ooo32gsl03.patch

    - Tue Dec 15 2009 Caolan McNamara <caolanm at
      redhat.com> - 1:3.1.1-19.22

    - Resolves: rhbz#529648 add workspace.fwk132.patch

    - Resolves: rhbz#547176 add
      openoffice.org-3.2.0.ooo47279.sd.objectsave.safe.patch

  - Wed Dec 9 2009 Caolan McNamara <caolanm at redhat.com> -
    1:3.1.1-19.21

    - Resolves: rhbz#544124 add
      openoffice.org-3.2.0.ooo106502.svx.fixspelltimer.patch

    - Resolves: rhbz#544218 add
      openoffice.org-3.2.0.ooo107552.vcl.sft.patch

    - Resolves: rhbz#545783 add workspace.vcl105.patch

    - Fri Nov 27 2009 Caolan McNamara <caolanm at
      redhat.com> - 1:3.1.1-19.20

    - Resolves: rhbz#541222 add
      openoffice.org-3.2.0.ooo107260.dtrans.clipboard.shutdo
      wn.patch (caolanm)

  - Mon Nov 23 2009 Caolan McNamara <caolanm at redhat.com>
    - 1:3.1.1-19.19

    - Resolves: rhbz#540379/ooo#107131 impress tabledrag
      crash

    - Resolves: rhbz#540231 add
      openoffice.org-3.2.0.oooXXXXX.canvas.fixcolorspace.pat
      ch

    - add
      openoffice.org-4.2.0.ooo107151.sc.pop-empty-cell.patch
      (dtardon)

    - Resolves: rhbz#533538 OpenOffice keyboard shortcuts
      mis-map in the Spanish localized version of OOo
      (caolanm)

  - Tue Nov 17 2009 Caolan McNamara <caolanm at redhat.com>
    - 1:3.1.1-19.18

    - Resolves: ooo#59648 sw .doc export scaling (caolanm)

    - Tue Nov 10 2009 Caolan McNamara <caolanm at
      redhat.com> - 1:3.1.1-19.17

    - Resolves: rhbz#533841 ooo#105710 svx
      loadstorenumbering (caolanm)

[plus 8 lines in the Changelog]

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=527540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533038"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=533043"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-February/035109.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7a24e1b6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openoffice.org package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
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
if (rpm_check(release:"FC12", reference:"openoffice.org-3.1.1-19.26.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openoffice.org");
}
