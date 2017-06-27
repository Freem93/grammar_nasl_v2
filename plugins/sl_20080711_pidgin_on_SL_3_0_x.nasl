#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60438);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:53 $");

  script_cve_id("CVE-2008-2927");

  script_name(english:"Scientific Linux Security Update : pidgin on SL 3.0.x , SL 4.x , SL 5.x");
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
"An integer overflow flaw was found in Pidgin's MSN protocol handler.
If a user received a malicious MSN message, it was possible to execute
arbitrary code with the permissions of the user running Pidgin.
(CVE-2008-2927)

Note: the default Pidgin privacy setting only allows messages from
users in the buddy list. This prevents arbitrary MSN users from
exploiting this flaw.

This update also addresses the following bug :

  - when attempting to connect to the ICQ network, Pidgin
    would fail to connect, present an alert saying the 'The
    client version you are using is too old', and
    de-activate the ICQ account. This update restores
    Pidgin's ability to connect to the ICQ network."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0807&L=scientific-linux-errata&T=0&P=554
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7142b4f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL3", cpu:"x86_64", reference:"pidgin-1.5.1-2.el3")) flag++;

if (rpm_check(release:"SL4", reference:"pidgin-1.5.1-2.el4")) flag++;

if (rpm_check(release:"SL5", reference:"finch-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"finch-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-perl-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"libpurple-tcl-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-devel-2.3.1-2.el5_2")) flag++;
if (rpm_check(release:"SL5", reference:"pidgin-perl-2.3.1-2.el5_2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
