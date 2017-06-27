#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(61010);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/04 10:44:09 $");

  script_cve_id("CVE-2008-2937", "CVE-2011-0411");

  script_name(english:"Scientific Linux Security Update : postfix on SL4.x, SL5.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that Postfix did not flush the received SMTP
commands buffer after switching to TLS encryption for an SMTP session.
A man-in-the-middle attacker could use this flaw to inject SMTP
commands into a victim's session during the plain text phase. This
would lead to those commands being processed by Postfix after TLS
encryption is enabled, possibly allowing the attacker to steal the
victim's mail or authentication credentials. (CVE-2011-0411)

It was discovered that Postfix did not properly check the permissions
of users' mailbox files. A local attacker able to create files in the
mail spool directory could use this flaw to create mailbox files for
other local users, and be able to read mail delivered to those users.
(CVE-2008-2937)

After installing this update, the postfix service will be restarted
automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1104&L=scientific-linux-errata&T=0&P=817
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81e0da8f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected postfix and / or postfix-pflogsumm packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(200);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/06");
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
if (rpm_check(release:"SL4", reference:"postfix-2.2.10-1.4.el4")) flag++;
if (rpm_check(release:"SL4", reference:"postfix-pflogsumm-2.2.10-1.4.el4")) flag++;

if (rpm_check(release:"SL5", reference:"postfix-2.3.3-2.2.el5_6")) flag++;
if (rpm_check(release:"SL5", reference:"postfix-pflogsumm-2.3.3-2.2.el5_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
