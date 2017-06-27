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
  script_id(42989);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-3025", "CVE-2009-3026", "CVE-2009-3083", "CVE-2009-3084", "CVE-2009-3085", "CVE-2009-3615");

  script_name(english:"SuSE 11 Security Update : pidgin (SAT Patch Number 1604)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of pidgin fixes the following issues :

  - Allowed to send confidential data unencrypted even if
    SSL was chosen by user. (CVE-2009-3026: CVSS v2 Base
    Score: 5.0)

  - Remote denial of service in yahoo IM plug-in.
    (CVE-2009-3025: CVSS v2 Base Score: 4.3)

  - Remote denial of service in MSN plug-in. (CVE-2009-3083:
    CVSS v2 Base Score: 5.0)

  - Remote denial of service in MSN plug-in. (CVE-2009-3084:
    CVSS v2 Base Score: 5.0)

  - Remote denial of service in XMPP plug-in.
    (CVE-2009-3085: CVSS v2 Base Score: 5.0)

  - Remote denial of service in ICQ plug-in. (CVE-2009-3615:
    CVSS v2 Base Score: 5.0)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535570"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=535832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=536602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=548072"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3025.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3026.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3083.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3084.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3085.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3615.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1604.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(20, 119, 310, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cdparanoia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:cdparanoia-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:desktop-file-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:fam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:fam-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:finch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gnome-vfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gnome-vfs2-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gstreamer-0_10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:gstreamer-0_10-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libogg0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libogg0-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:liboil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:liboil-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpurple-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pidgin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:pidgin-otr");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"cdparanoia-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"desktop-file-utils-0.15-1.29")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"fam-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"finch-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gnome-vfs2-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"gstreamer-0_10-0.10.21-3.20")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libogg0-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"liboil-0.3.15-3.10")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libpurple-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"libpurple-lang-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"pidgin-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"pidgin-otr-3.2.0-1.36.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"cdparanoia-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"cdparanoia-32bit-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"desktop-file-utils-0.15-1.29")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"fam-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"fam-32bit-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"finch-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gnome-vfs2-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gnome-vfs2-32bit-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gstreamer-0_10-0.10.21-3.20")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"gstreamer-0_10-32bit-0.10.21-3.20")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libogg0-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libogg0-32bit-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"liboil-0.3.15-3.10")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"liboil-32bit-0.3.15-3.10")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libpurple-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"libpurple-lang-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"pidgin-2.6.3-0.1.1")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"pidgin-otr-3.2.0-1.36.1")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"cdparanoia-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"desktop-file-utils-0.15-1.29")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"fam-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"gnome-vfs2-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"gstreamer-0_10-0.10.21-3.20")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"libogg0-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLES11", sp:0, reference:"liboil-0.3.15-3.10")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"cdparanoia-32bit-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"fam-32bit-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"gnome-vfs2-32bit-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"libogg0-32bit-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"s390x", reference:"liboil-32bit-0.3.15-3.10")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"cdparanoia-32bit-IIIalpha9.8-691.22")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"fam-32bit-2.7.0-130.21")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"gnome-vfs2-32bit-2.24.0-7.4")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"libogg0-32bit-1.1.3-87.12")) flag++;
if (rpm_check(release:"SLES11", sp:0, cpu:"x86_64", reference:"liboil-32bit-0.3.15-3.10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
