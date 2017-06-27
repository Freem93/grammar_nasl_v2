#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:1458-3.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83848);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:21 $");

  script_cve_id("CVE-2014-1574", "CVE-2014-1575", "CVE-2014-1576", "CVE-2014-1577", "CVE-2014-1578", "CVE-2014-1581", "CVE-2014-1583", "CVE-2014-1585", "CVE-2014-1586");
  script_bugtraq_id(70424, 70425, 70426, 70427, 70428, 70430, 70436, 70439, 70440);
  script_osvdb_id(113141, 113142, 113143, 113144, 113145, 113146, 113147, 113148, 113149, 113150, 113151, 113152, 113159, 113160, 113161, 113162, 113163, 113165, 113166, 113209);

  script_name(english:"SUSE SLES10 Security Update : MozillaFirefox (SUSE-SU-2014:1458-3)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This version update of Mozilla Firefox to 31.2.0ESR brings
improvements, stability fixes and also security fixes for the
following CVEs :

CVE-2014-1574, CVE-2014-1575, CVE-2014-1576 ,CVE-2014-1577,
CVE-2014-1578, CVE-2014-1581, CVE-2014-1583, CVE-2014-1585,
CVE-2014-1586

It also disables SSLv3 by default to mitigate the protocol downgrade
attack known as POODLE.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=caf12701f26397664ab064794563a9cc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e4a4ecac"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1574.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1575.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1576.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1581.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1583.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1585.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-1586.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=900941"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=905528"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20141458-3.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3d33b30e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected MozillaFirefox packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-branding-SLED");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:MozillaFirefox-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES10" && (! ereg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.10.7-0.5.4")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"mozilla-nss-32bit-3.17.2-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"mozilla-nspr-32bit-4.10.7-0.5.4")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"mozilla-nss-32bit-3.17.2-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nspr-4.10.7-0.5.4")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nspr-devel-4.10.7-0.5.4")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-3.17.2-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-devel-3.17.2-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"mozilla-nss-tools-3.17.2-0.5.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-31.2.0esr-0.11.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-branding-SLED-31.0-0.7.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"MozillaFirefox-translations-31.2.0esr-0.11.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "MozillaFirefox");
}
