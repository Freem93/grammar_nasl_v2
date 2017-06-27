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
  script_id(57841);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2011-2686", "CVE-2011-2705", "CVE-2011-3009", "CVE-2011-4815");

  script_name(english:"SuSE 11.1 Security Update : ruby (SAT Patch Number 5716)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of ruby provides 1.8.7p357, which contains many stability
fixes and bug fixes while maintaining full compatibility with the
previous version. A detailailed list of changes is available from
http://svn.ruby-lang.org/repos/ruby/tags/v1_8_7_357/ChangeLog .

The most important fixes are :

  - Hash functions are now using a randomized seed to avoid
    algorithmic complexity attacks. If available,
    OpenSSL::Random.seed at the SecureRandom.random_bytes is
    used to achieve this. (CVE-2011-4815)

  - mkconfig.rb: fix for continued lines.

  - Fix Infinity to be greater than any bignum number.

  - Initialize store->ex_data.sk.

  - Several IPv6 related fixes.

  - Fixes for zlib.

  - Reinitialize PRNG when forking children. (CVE-2011-2686
    / CVE-2011-3009)

  - Fixes to securerandom. (CVE-2011-2705)

  - Fix uri route_to

  - Fix race condition with variables and autoload."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=704409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=739122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=740796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2686.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-2705.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-3009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2011-4815.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 5716.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby-doc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:ruby-tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2013 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:1, cpu:"i586", reference:"ruby-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ruby-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ruby-doc-html-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"i586", reference:"ruby-tk-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"ruby-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"ruby-doc-html-1.8.7.p357-0.7.1")) flag++;
if (rpm_check(release:"SLES11", sp:1, cpu:"s390x", reference:"ruby-tk-1.8.7.p357-0.7.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
