#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from SuSE 11 update information. The text itself is
# copyright (C) Novell, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64209);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/10/25 23:52:02 $");

  script_cve_id("CVE-2009-2408");

  script_name(english:"SuSE 11 Security Update : Mozilla (SAT Patch Number 1304)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 11 host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird was updated to version 2.0.0.23.

The release fixes one security issue: MFSA 2009-42 / CVE-2009-2408:
IOActive security researcher Dan Kaminsky reported a mismatch in the
treatment of domain names in SSL certificates between SSL clients and
the Certificate Authorities (CA) which issue server certificates. In
particular, if a malicious person requested a certificate for a host
name with an invalid null character in it most CAs would issue the
certificate if the requester owned the domain specified after the
null, while most SSL clients (browsers) ignored that part of the name
and used the unvalidated part in front of the null. This made it
possible for attackers to obtain certificates that would function for
any site they wished to target. These certificates could be used to
intercept and potentially alter encrypted communication between the
client and a server such as sensitive bank account transactions. This
vulnerability was independently reported to us by researcher Moxie
Marlinspike who also noted that since Firefox relies on SSL to protect
the integrity of security updates this attack could be used to serve
malicious updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.mozilla.org/security/announce/2009/mfsa2009-42.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=534782"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-2408.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply SAT patch number 1304.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaThunderbird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:MozillaThunderbird-translations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:11:hunspell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/25");
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
if (pl) audit(AUDIT_OS_NOT, "SuSE 11.0");


flag = 0;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaThunderbird-2.0.0.23-0.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"MozillaThunderbird-translations-2.0.0.23-0.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"i586", reference:"hunspell-1.2.7-1.16")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaThunderbird-2.0.0.23-0.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"MozillaThunderbird-translations-2.0.0.23-0.2.2")) flag++;
if (rpm_check(release:"SLED11", sp:0, cpu:"x86_64", reference:"hunspell-1.2.7-1.16")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
