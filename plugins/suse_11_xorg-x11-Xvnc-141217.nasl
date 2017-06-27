#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(80547);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/15 15:44:12 $");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102");

  script_name(english:"SuSE 11.3 Security Update : xorg-x11-server (SAT Patch Number 10108)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The XOrg X11 server was updated to fix 12 security issues :

  - Denial of service due to unchecked malloc in client
    authentication. (CVE-2014-8091)

  - Integer overflows calculating memory needs for requests.
    (CVE-2014-8092)

  - Integer overflows calculating memory needs for requests
    in GLX extension. (CVE-2014-8093)

  - Integer overflows calculating memory needs for requests
    in DRI2 extension. (CVE-2014-8094)

  - Out of bounds access due to not validating length or
    offset values in requests in XInput extension.
    (CVE-2014-8095)

  - Out of bounds access due to not validating length or
    offset values in requests in XC-MISC extension.
    (CVE-2014-8096)

  - Out of bounds access due to not validating length or
    offset values in requests in DBE extension.
    (CVE-2014-8097)

  - Out of bounds access due to not validating length or
    offset values in requests in GLX extension.
    (CVE-2014-8098)

  - Out of bounds access due to not validating length or
    offset values in requests in XVideo extension.
    (CVE-2014-8099)

  - Out of bounds access due to not validating length or
    offset values in requests in Render extension.
    (CVE-2014-8100)

  - Out of bounds access due to not validating length or
    offset values in requests in RandR extension.
    (CVE-2014-8101)

  - Out of bounds access due to not validating length or
    offset values in requests in XFixes extension
    (CVE-2014-8102). Additionally, these non-security issues
    were fixed :

  - Fix crash in RENDER protocol, PanoramiX wrappers.
    (bnc#864911)

  - Some formats used for pictures did not work with the
    chosen framebuffer format. (bnc#886213)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864911"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=886213"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907268"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=907633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8091.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8093.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8095.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8096.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8097.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8098.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8099.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8100.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8101.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-8102.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 10108.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-Xvnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:xorg-x11-server-extra");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 3) audit(AUDIT_OS_NOT, "SuSE 11.3");


flag = 0;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-Xvnc-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-server-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"xorg-x11-server-extra-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-Xvnc-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-server-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"xorg-x11-server-extra-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-Xvnc-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-server-7.4-27.101.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"xorg-x11-server-extra-7.4-27.101.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
