#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60195);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/08/01 14:38:52 $");

  script_cve_id("CVE-2006-5297", "CVE-2007-1558", "CVE-2007-2683");

  script_name(english:"Scientific Linux Security Update : mutt on SL5.x, SL4.x, SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was found in the way Mutt used temporary files on NFS file
systems. Due to an implementation issue in the NFS protocol, Mutt was
not able to exclusively open a new file. A local attacker could
conduct a time-dependent attack and possibly gain access to e-mail
attachments opened by a victim. (CVE-2006-5297)

A flaw was found in the way Mutt processed certain APOP authentication
requests. By sending certain responses when mutt attempted to
authenticate against an APOP server, a remote attacker could
potentially acquire certain portions of a user's authentication
credentials. (CVE-2007-1558)

A flaw was found in the way Mutt handled certain characters in gecos
fields which could lead to a buffer overflow. The gecos field is an
entry in the password database typically used to record general
information about the user. A local attacker could give themselves a
carefully crafted 'Real Name' which could execute arbitrary code if a
victim uses Mutt and expands the attackers alias. (CVE-2007-2683)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0706&L=scientific-linux-errata&T=0&P=840
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?da53416f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected mutt package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/04");
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
if (rpm_check(release:"SL3", reference:"mutt-1.4.1-5.el3")) flag++;

if (rpm_check(release:"SL4", reference:"mutt-1.4.1-12.0.3.el4")) flag++;

if (rpm_check(release:"SL5", reference:"mutt-1.4.2.2-3.0.2.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
