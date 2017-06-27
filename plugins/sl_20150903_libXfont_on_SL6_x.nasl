#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(85788);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/09/04 13:51:06 $");

  script_cve_id("CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804");

  script_name(english:"Scientific Linux Security Update : libXfont on SL6.x, SL7.x i386/x86_64");
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
"An integer overflow flaw was found in the way libXfont processed
certain Glyph Bitmap Distribution Format (BDF) fonts. A malicious,
local user could use this flaw to crash the X.Org server or,
potentially, execute arbitrary code with the privileges of the X.Org
server. (CVE-2015-1802)

An integer truncation flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server
or, potentially, execute arbitrary code with the privileges of the
X.Org server. (CVE-2015-1804)

A NULL pointer dereference flaw was discovered in the way libXfont
processed certain Glyph Bitmap Distribution Format (BDF) fonts. A
malicious, local user could use this flaw to crash the X.Org server.
(CVE-2015-1803)"
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1509&L=scientific-linux-errata&F=&S=&P=6185
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fa7f5f18"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libXfont, libXfont-debuginfo and / or
libXfont-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"libXfont-1.4.5-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-debuginfo-1.4.5-5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"libXfont-devel-1.4.5-5.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-1.4.7-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-debuginfo-1.4.7-3.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libXfont-devel-1.4.7-3.el7_1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
