#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61240);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/08/16 19:47:27 $");

  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");

  script_name(english:"Scientific Linux Security Update : squirrelmail on SL4.x, SL5.x");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"SquirrelMail is a standards-based webmail package written in PHP.

A cross-site scripting (XSS) flaw was found in the way SquirrelMail
performed the sanitization of HTML style tag content. A remote
attacker could use this flaw to send a specially crafted Multipurpose
Internet Mail Extensions (MIME) message that, when opened by a victim,
would lead to arbitrary web script execution in the context of their
SquirrelMail session. (CVE-2011-2023)

Multiple cross-site scripting (XSS) flaws were found in SquirrelMail.
A remote attacker could possibly use these flaws to execute arbitrary
web script in the context of a victim's SquirrelMail session.
(CVE-2010-4555)

An input sanitization flaw was found in the way SquirrelMail handled
the content of various HTML input fields. A remote attacker could use
this flaw to alter user preference values via a newline character
contained in the input for these fields. (CVE-2011-2752)

It was found that the SquirrelMail Empty Trash and Index Order pages
did not protect against Cross-Site Request Forgery (CSRF) attacks. If
a remote attacker could trick a user, who was logged into
SquirrelMail, into visiting a specially crafted URL, the attacker
could empty the victim's trash folder or alter the ordering of the
columns on the message index page. (CVE-2011-2753)

SquirrelMail was allowed to be loaded into an HTML sub-frame, allowing
a remote attacker to perform a clickjacking attack against logged in
users and possibly gain access to sensitive user data. With this
update, the SquirrelMail main frame can only be loaded into the top
most browser frame. (CVE-2010-4554)

A flaw was found in the way SquirrelMail handled failed log in
attempts. A user preference file was created when attempting to log in
with a password containing an 8-bit character, even if the username
was not valid. A remote attacker could use this flaw to eventually
consume all hard disk space on the target SquirrelMail server.
(CVE-2010-2813)

A flaw was found in the SquirrelMail Mail Fetch plug-in. If an
administrator enabled this plug-in, a SquirrelMail user could use this
flaw to port scan the local network the server was on. (CVE-2010-1637)

Users of SquirrelMail should upgrade to this updated package, which
contains backported patches to correct these issues."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=1503
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d301d720"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL4", reference:"squirrelmail-1.4.8-18.el4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
