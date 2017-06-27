#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2012:0103 and 
# Oracle Linux Security Advisory ELSA-2012-0103 respectively.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(68452);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/06 17:02:14 $");

  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_bugtraq_id(40291, 42399, 48648);
  script_osvdb_id(65696, 67245, 74083, 74084, 74085, 74086, 74087, 74088, 74089);
  script_xref(name:"RHSA", value:"2012:0103");

  script_name(english:"Oracle Linux 4 / 5 : squirrelmail (ELSA-2012-0103)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2012:0103 :

An updated squirrelmail package that fixes several security issues is
now available for Red Hat Enterprise Linux 4 and 5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

SquirrelMail is a standards-based webmail package written in PHP.

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
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-February/002597.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2012-February/002598.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"squirrelmail-1.4.8-18.0.1.el4")) flag++;

if (rpm_check(release:"EL5", reference:"squirrelmail-1.4.8-5.0.1.el5_7.13")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
}
