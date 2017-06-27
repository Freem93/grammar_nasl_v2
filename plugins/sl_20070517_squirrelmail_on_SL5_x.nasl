#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60185);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_cve_id("CVE-2007-1262", "CVE-2007-2589");

  script_name(english:"Scientific Linux Security Update : squirrelmail on SL5.x, SL4.x, SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several HTML filtering bugs were discovered in SquirrelMail. An
attacker could inject arbitrary JavaScript leading to cross-site
scripting attacks by sending an e-mail viewed by a user within
SquirrelMail. (CVE-2007-1262)

Squirrelmail did not sufficiently check arguments to IMG tags in HTML
e-mail messages. This could be exploited by an attacker by sending
arbitrary e-mail messages on behalf of a squirrelmail user tricked
into opening a maliciously crafted HTML e-mail message.
(CVE-2007-2589)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0705&L=scientific-linux-errata&T=0&P=3046
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?98b562b4"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected squirrelmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_cwe_id(79, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/17");
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
if (rpm_check(release:"SL3", reference:"squirrelmail-1.4.8-6.el3")) flag++;

if (rpm_check(release:"SL4", reference:"squirrelmail-1.4.8-4.0.1.el4")) flag++;

if (rpm_check(release:"SL5", reference:"squirrelmail-1.4.8-4.0.1.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
