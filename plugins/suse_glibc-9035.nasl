#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81125);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/22 20:32:46 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");

  script_name(english:"SuSE 10 Security Update : glibc (ZYPP Patch Number 9035)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for glibc fixes the following security issue :

  - A vulnerability was found and fixed in the GNU C
    Library, specifically in the function gethostbyname(),
    that can lead to a local or remote buffer overflow.
    (bsc#913646). (CVE-2015-0235)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=913646"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2015-0235.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 9035.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-locale-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:10:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/02");
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
if (isnull(release) || release !~ "^SLES10") audit(AUDIT_OS_NOT, "SuSE 10");
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SuSE 10", cpu);


flag = 0;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-devel-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-html-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-i18ndata-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-info-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-locale-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"glibc-profile-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"nscd-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"glibc-32bit-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"glibc-devel-32bit-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"glibc-locale-32bit-2.4-31.113.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"glibc-profile-32bit-2.4-31.113.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
