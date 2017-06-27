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
  script_id(73268);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/18 15:00:16 $");

  script_cve_id("CVE-2014-0060", "CVE-2014-0061", "CVE-2014-0062", "CVE-2014-0063", "CVE-2014-0064", "CVE-2014-0065", "CVE-2014-0066", "CVE-2014-0067");

  script_name(english:"SuSE 11.3 Security Update : PostgreSQL 9.1 (SAT Patch Number 8970)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The PostgreSQL database server was updated to version 9.1.12 to fix
various security issues :

  - Granting a role without ADMIN OPTION is supposed to
    prevent the grantee from adding or removing members from
    the granted role, but this restriction was easily
    bypassed by doing SET ROLE first. The security impact is
    mostly that a role member can revoke the access of
    others, contrary to the wishes of his grantor.
    Unapproved role member additions are a lesser concern,
    since an uncooperative role member could provide most of
    his rights to others anyway by creating views or
    SECURITY DEFINER functions. (CVE-2014-0060)

  - The primary role of PL validator functions is to be
    called implicitly during CREATE FUNCTION, but they are
    also normal SQL functions that a user can call
    explicitly. Calling a validator on a function actually
    written in some other language was not checked for and
    could be exploited for privilege-escalation purposes.
    The fix involves adding a call to a privilege-checking
    function in each validator function. Non-core procedural
    languages will also need to make this change to their
    own validator functions, if any. (CVE-2014-0061)

  - If the name lookups come to different conclusions due to
    concurrent activity, we might perform some parts of the
    DDL on a different table than other parts. At least in
    the case of CREATE INDEX, this can be used to cause the
    permissions checks to be performed against a different
    table than the index creation, allowing for a privilege
    escalation attack. (CVE-2014-0062)

  - The MAXDATELEN constant was too small for the longest
    possible value of type interval, allowing a buffer
    overrun in interval_out(). Although the datetime input
    functions were more careful about avoiding buffer
    overrun, the limit was short enough to cause them to
    reject some valid inputs, such as input containing a
    very long timezone name. The ecpg library contained
    these vulnerabilities along with some of its own.
    (CVE-2014-0063)

  - Several functions, mostly type input functions,
    calculated an allocation size without checking for
    overflow. If overflow did occur, a too-small buffer
    would be allocated and then written past.
    (CVE-2014-0064)

  - Use strlcpy() and related functions to provide a clear
    guarantee that fixed-size buffers are not overrun.
    Unlike the preceding items, it is unclear whether these
    cases really represent live issues, since in most cases
    there appear to be previous constraints on the size of
    the input string. Nonetheless it seems prudent to
    silence all Coverity warnings of this type.
    (CVE-2014-0065)

  - There are relatively few scenarios in which crypt()
    could return NULL, but contrib/chkpass would crash if it
    did. One practical case in which this could be an issue
    is if libc is configured to refuse to execute unapproved
    hashing algorithms (e.g., 'FIPS mode'). (CVE-2014-0066)

  - Since the temporary server started by make check uses
    'trust' authentication, another user on the same machine
    could connect to it as database superuser, and then
    potentially exploit the privileges of the
    operating-system user who started the tests. A future
    release will probably incorporate changes in the testing
    procedure to prevent this risk, but some public
    discussion is needed first. So for the moment, just warn
    people against using make check when there are untrusted
    users on the same machine. (CVE-2014-0067)

The complete list of bugs and more information can be found at:
http://www.postgresql.org/docs/9.1/static/release-9-1-12.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864845"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864846"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864847"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864850"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864852"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=864853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0060.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0061.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0062.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0063.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0064.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0065.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0066.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0067.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 8970.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:postgresql91-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libecpg6-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"libpq5-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"postgresql91-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"i586", reference:"postgresql91-docs-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libecpg6-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpq5-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"libpq5-32bit-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"postgresql91-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLED11", sp:3, cpu:"x86_64", reference:"postgresql91-docs-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libecpg6-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"libpq5-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-contrib-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-docs-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, reference:"postgresql91-server-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"s390x", reference:"libpq5-32bit-9.1.12-0.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:3, cpu:"x86_64", reference:"libpq5-32bit-9.1.12-0.3.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
