#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0103. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57870);
  script_version ("$Revision: 1.13 $");
  script_cvs_date("$Date: 2017/01/05 16:04:21 $");

  script_cve_id("CVE-2010-1637", "CVE-2010-2813", "CVE-2010-4554", "CVE-2010-4555", "CVE-2011-2023", "CVE-2011-2752", "CVE-2011-2753");
  script_bugtraq_id(40291, 42399, 48648);
  script_osvdb_id(65696, 67245, 74083, 74084, 74085, 74086, 74087, 74088, 74089);
  script_xref(name:"RHSA", value:"2012:0103");

  script_name(english:"RHEL 4 / 5 : squirrelmail (RHSA-2012:0103)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated squirrelmail package that fixes several security issues is
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
    value:"https://www.redhat.com/security/data/cve/CVE-2010-1637.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2813.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4554.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-4555.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2752.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-2753.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squirrelmail.org/security/issue/2010-06-21"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squirrelmail.org/security/issue/2010-07-23"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squirrelmail.org/security/issue/2011-07-10"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squirrelmail.org/security/issue/2011-07-11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.squirrelmail.org/security/issue/2011-07-12"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2012-0103.html"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squirrelmail");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 4.x / 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2012:0103";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL4", reference:"squirrelmail-1.4.8-18.el4")) flag++;

  if (rpm_check(release:"RHEL5", reference:"squirrelmail-1.4.8-5.el5_7.13")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squirrelmail");
  }
}
