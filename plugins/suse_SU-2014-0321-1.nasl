#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0321-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(83612);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2015/05/20 15:11:10 $");

  script_cve_id("CVE-2009-5138", "CVE-2014-0092");
  script_bugtraq_id(65792, 65919);
  script_osvdb_id(103933);

  script_name(english:"SUSE SLES10 Security Update : gnutls (SUSE-SU-2014:0321-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The GnuTLS library received a critical security fix and other 
updates :

  - CVE-2014-0092: The X.509 certificate verification had
    incorrect error handling, which could lead to broken
    certificates marked as being valid.

  - CVE-2009-5138: A verification problem in handling V1
    certificates could also lead to V1 certificates
    incorrectly being handled.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.novell.com/patch/finder/?keywords=37d0e9642492b343b6f431f0fecb7b5b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0db942d7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2014-0092.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/865804"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/865993"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140321-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?672158b3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gnutls packages"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
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
if (os_ver == "SLES10" && (! ereg(pattern:"^4$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"gnutls-32bit-1.2.10-13.38.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"x86_64", reference:"gnutls-devel-32bit-1.2.10-13.38.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"gnutls-32bit-1.2.10-13.38.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", cpu:"s390x", reference:"gnutls-devel-32bit-1.2.10-13.38.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"gnutls-1.2.10-13.38.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"gnutls-devel-1.2.10-13.38.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls");
}
