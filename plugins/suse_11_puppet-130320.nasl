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
  script_id(65796);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:56:04 $");

  script_cve_id("CVE-2013-1640", "CVE-2013-1652", "CVE-2013-1653", "CVE-2013-1654", "CVE-2013-1655", "CVE-2013-2274", "CVE-2013-2275");

  script_name(english:"SuSE 11.2 Security Update : puppet (SAT Patch Number 7526)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"puppet has been updated to fix 2.6.18 multiple vulnerabilities and
bugs.

  - (#19391) Find the catalog for the specified node name

  - Don't assume master supports SSLv2

  - Don't require openssl client to return 0 on failure

  - Display SSL messages so we can match our regex

  - Don't assume puppetbindir is defined

  - Remove unnecessary rubygems require

  - Run openssl from windows when trying to downgrade master

  - Separate tests for same CVEs into separate files

  - Fix order-dependent test failure in rest_authconfig_spec

  - Always read request body when using Rack

  - (#19392) (CVE-2013-1653) Fix acceptance test to catch
    unvalidated model on 2.6

  - (#19392) (CVE-2013-1653) Validate indirection model in
    save handler

  - Acceptance tests for CVEs 2013 (1640, 1652, 1653, 1654,
    2274, 2275)

  - (#19531) (CVE-2013-2275) Only allow report save from the
    node matching the certname

  - (#19391) Backport Request#remote? method

  - (#8858) Explicitly set SSL peer verification mode.

  - (#8858) Refactor tests to use real HTTP objects

  - (#19392) (CVE-2013-1653) Validate instances passed to
    indirector

  - (#19391) (CVE-2013-1652) Disallow use_node compiler
    parameter for remote requests

  - (#19151) Reject SSLv2 SSL handshakes and ciphers

  - (#14093) Restore access to the filename in the template

  - (#14093) Remove unsafe attributes from TemplateWrapper"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=809839"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1640.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1652.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1653.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1654.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-1655.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2274.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-2275.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 7526.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:puppet-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if (isnull(pl) || int(pl) != 2) audit(AUDIT_OS_NOT, "SuSE 11.2");


flag = 0;
if (rpm_check(release:"SLED11", sp:2, cpu:"i586", reference:"puppet-2.6.18-0.4.2")) flag++;
if (rpm_check(release:"SLED11", sp:2, cpu:"x86_64", reference:"puppet-2.6.18-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"puppet-2.6.18-0.4.2")) flag++;
if (rpm_check(release:"SLES11", sp:2, reference:"puppet-server-2.6.18-0.4.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
