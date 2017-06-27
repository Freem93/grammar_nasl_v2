#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2015:0953-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83868);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/02 15:19:31 $");

  script_cve_id("CVE-2013-6393", "CVE-2014-2525", "CVE-2014-9130");
  script_bugtraq_id(65258, 66478, 71349);
  script_osvdb_id(105027, 115190);

  script_name(english:"SUSE SLES12 Security Update : perl-YAML-LibYAML (SUSE-SU-2015:0953-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"perl-YAML-LibYAML was updated to fix three security issues.

These security issues were fixed :

  - CVE-2013-6393: The yaml_parser_scan_tag_uri function in
    scanner.c in LibYAML before 0.1.5 performed an incorrect
    cast, which allowed remote attackers to cause a denial
    of service (application crash) and possibly execute
    arbitrary code via crafted tags in a YAML document,
    which triggered a heap-based buffer overflow
    (bnc#860617, bnc#911782).

  - CVE-2014-9130: scanner.c in LibYAML 0.1.5 and 0.1.6, as
    used in the YAML-LibYAML (aka YAML-XS) module for Perl,
    allowed context-dependent attackers to cause a denial of
    service (assertion failure and crash) via vectors
    involving line-wrapping (bnc#907809, bnc#911782).

  - CVE-2014-2525: Heap-based buffer overflow in the
    yaml_parser_scan_uri_escapes function in LibYAML before
    0.1.6 allowed context-dependent attackers to execute
    arbitrary code via a long sequence of percent-encoded
    characters in a URI in a YAML file (bnc#868944,
    bnc#911782).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/860617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/868944"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/907809"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/911782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2013-6393.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-2525.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2014-9130.html"
  );
  # https://www.suse.com/support/update/announcement/2015/suse-su-20150953-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0d7c667b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 12 :

zypper in -t patch SUSE-SLE-SERVER-12-2015-215=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-YAML-LibYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-YAML-LibYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:perl-YAML-LibYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/28");
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
if (! ereg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);
if (cpu >!< "s390x") audit(AUDIT_ARCH_NOT, "s390x", cpu);


sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"perl-YAML-LibYAML-0.38-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"perl-YAML-LibYAML-debuginfo-0.38-10.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", cpu:"s390x", reference:"perl-YAML-LibYAML-debugsource-0.38-10.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-YAML-LibYAML");
}
