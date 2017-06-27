#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60519);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/14 20:22:13 $");

  script_cve_id("CVE-2008-2379", "CVE-2008-3663");

  script_name(english:"Scientific Linux Security Update : squirrelmail on SL3.x, SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ivan Markovic discovered a cross-site scripting (XSS) flaw in
SquirrelMail caused by insufficient HTML mail sanitization. A remote
attacker could send a specially crafted HTML mail or attachment that
could cause a user's Web browser to execute a malicious script in the
context of the SquirrelMail session when that email or attachment was
opened by the user. (CVE-2008-2379)

It was discovered that SquirrelMail allowed cookies over insecure
connections (ie did not restrict cookies to HTTPS connections). An
attacker who controlled the communication channel between a user and
the SquirrelMail server, or who was able to sniff the user's network
communication, could use this flaw to obtain the user's session
cookie, if a user made an HTTP request to the server. (CVE-2008-3663)

Note: After applying this update, all session cookies set for
SquirrelMail sessions started over HTTPS connections will have the
'secure' flag set. That is, browsers will only send such cookies over
an HTTPS connection. If needed, you can revert to the previous
behavior by setting the configuration option '$only_secure_cookies' to
'false' in SquirrelMail's /etc/squirrelmail/config.php configuration
file."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0901&L=scientific-linux-errata&T=0&P=1051
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a3ba025"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cwe_id(79, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", reference:"squirrelmail-1.4.8-8.el3")) flag++;

if (rpm_check(release:"SL4", reference:"squirrelmail-1.4.8-5.el4_7.2")) flag++;

if (rpm_check(release:"SL5", reference:"squirrelmail-1.4.8-5.el5_2.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
