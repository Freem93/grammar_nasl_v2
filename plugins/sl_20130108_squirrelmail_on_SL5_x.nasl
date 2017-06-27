#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63604);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/01/17 14:07:22 $");

  script_cve_id("CVE-2010-2813", "CVE-2012-2124");

  script_name(english:"Scientific Linux Security Update : squirrelmail on SL5.x (noarch)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SquirrelMail security update SLSA-2012:0103 did not, unlike the
erratum text stated, correct the CVE-2010-2813 issue, a flaw in the
way SquirrelMail handled failed log in attempts. A user preference
file was created when attempting to log in with a password containing
an 8-bit character, even if the username was not valid. A remote
attacker could use this flaw to eventually consume all hard disk space
on the target SquirrelMail server. (CVE-2012-2124)

This update also fixes the following bugs :

  - Prior to this update, SquirrelMail could not decode
    multi-line subjects properly. Consequently, the decode
    header internationalization option did not properly
    handle new lines or tabs at the beginning of the lines.
    This bug has been fixed and SquirrelMail now works
    correctly in the described scenario.

  - Due to a bug, attachments written in HTML code on the
    Windows operating system were not displayed properly
    when accessed with SquirrelMail; the '!=null' string was
    trimmed to '!ull'. This bug has been fixed and the
    attachments are now displayed correctly in such a case.

  - Previously, e-mail messages with a Unique Identifier
    (UID) larger than 2^31 bytes were unreadable when using
    the squirrelmail package. With this patch the
    squirrelmail package is able to read all messages
    regardless of the UIDs size.

  - Due to a bug, a PHP script did not assign the proper
    character set to requested variables. Consequently,
    SquirrelMail could not display any e-mails. The
    underlying source code has been modified and now the
    squirrelmail package assigns the correct character set.

  - Due to the incorrect internationalization option located
    at the i18n.php file, the squirrelmail package could not
    use the GB 2312 character set. The i18n.php file has
    been fixed and the GB 2312 character set works correctly
    in the described scenario.

  - Previously, the preg_split() function contained a
    misspelled constant, PREG_SPLIT_NI_EMPTY, which could
    cause SquirrelMail to produce error messages. The name
    of the constant has been corrected to
    PREG_SPLIT_NO_EMPTY, and SquirrelMail no longer produces
    error messages in this scenario.

  - Due to Security-Enhanced Linux (SELinux) settings,
    sending e-mails from the SquirrelMail web interface was
    blocked. This update adds a note to the SquirrelMail
    documentation that describes how to set the SELinux
    options to allow sending e-mails from the SquirrelMail
    web interface.

  - Previously, the squirrelmail package did not comply with
    the RFC 2822 specification about line length limits.
    Consequently, attachments with lines longer than 998
    characters could not be forwarded using SquirrelMail.
    This patch modifies the underlying source code and now
    SquirrelMail complies with the RFC 2822 specification as
    expected.

  - Prior to this update, the squirrelmail package required
    the php-common script instead of the mod_php script
    during installation or upgrade of the package, which led
    to a dependency error. As a result, attempting to
    install or upgrade the squirrelmail package failed on
    systems using the php53 packages. With this update, the
    dependencies of the squirrelmail package were changed
    and the installation or upgrade now works correctly in
    the described scenario."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=577
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?51b2448c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"squirrelmail-1.4.8-21.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
