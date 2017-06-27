#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(61727);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2012-1970", "CVE-2012-1972", "CVE-2012-1973", "CVE-2012-1974", "CVE-2012-1975", "CVE-2012-1976", "CVE-2012-3956", "CVE-2012-3957", "CVE-2012-3958", "CVE-2012-3959", "CVE-2012-3960", "CVE-2012-3961", "CVE-2012-3962", "CVE-2012-3963", "CVE-2012-3964", "CVE-2012-3966", "CVE-2012-3967", "CVE-2012-3968", "CVE-2012-3969", "CVE-2012-3970", "CVE-2012-3972", "CVE-2012-3978", "CVE-2012-3980");

  script_name(english:"Scientific Linux Security Update : thunderbird on SL5.x, SL6.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Scientific Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mozilla Thunderbird is a standalone mail and newsgroup client.

Several flaws were found in the processing of malformed content.
Malicious content could cause Thunderbird to crash or, potentially,
execute arbitrary code with the privileges of the user running
Thunderbird. (CVE-2012-1970, CVE-2012-1972, CVE-2012-1973,
CVE-2012-1974, CVE-2012-1975, CVE-2012-1976, CVE-2012-3956,
CVE-2012-3957, CVE-2012-3958, CVE-2012-3959, CVE-2012-3960,
CVE-2012-3961, CVE-2012-3962, CVE-2012-3963, CVE-2012-3964)

Content containing a malicious Scalable Vector Graphics (SVG) image
file could cause Thunderbird to crash or, potentially, execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-3969, CVE-2012-3970)

Two flaws were found in the way Thunderbird rendered certain images
using WebGL. Malicious content could cause Thunderbird to crash or,
under certain conditions, possibly execute arbitrary code with the
privileges of the user running Thunderbird. (CVE-2012-3967,
CVE-2012-3968)

A flaw was found in the way Thunderbird decoded embedded bitmap images
in Icon Format (ICO) files. Content containing a malicious ICO file
could cause Thunderbird to crash or, under certain conditions,
possibly execute arbitrary code with the privileges of the user
running Thunderbird. (CVE-2012-3966)

A flaw was found in the way the 'eval' command was handled by the
Thunderbird Error Console. Running 'eval' in the Error Console while
viewing malicious content could possibly cause Thunderbird to execute
arbitrary code with the privileges of the user running Thunderbird.
(CVE-2012-3980)

An out-of-bounds memory read flaw was found in the way Thunderbird
used the format-number feature of XSLT (Extensible Stylesheet Language
Transformations). Malicious content could possibly cause an
information leak, or cause Thunderbird to crash. (CVE-2012-3972)

A flaw was found in the location object implementation in Thunderbird.
Malicious content could use this flaw to possibly allow restricted
content to be loaded. (CVE-2012-3978)

Note: All issues except CVE-2012-3969 and CVE-2012-3970 cannot be
exploited by a specially crafted HTML mail message as JavaScript is
disabled by default for mail messages. They could be exploited another
way in Thunderbird, for example, when viewing the full remote content
of an RSS feed.

All Thunderbird users should upgrade to this updated package, which
contains Thunderbird version 10.0.7 ESR, which corrects these issues.
After installing the update, Thunderbird must be restarted for the
changes to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=3199
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?383e527d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected thunderbird package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/30");
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
if (rpm_check(release:"SL5", reference:"thunderbird-10.0.7-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"thunderbird-10.0.7-1.el6_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
