#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49758);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/23 18:21:33 $");

  script_cve_id("CVE-2008-1391", "CVE-2010-0296", "CVE-2010-0830");

  script_name(english:"SuSE9 Security Update : glibc (YOU Patch Number 12641)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 9 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues were fixed :

  - Integer overflow causing arbitrary code execution in
    ld.so --verify mode could be induced by a specially
    crafted binary. (CVE-2010-0830)

  - The addmntent() function would not escape the newline
    character properly, allowing the user to insert
    arbitrary newlines to the /etc/mtab; if the addmntent()
    is run by a setuid mount binary that does not do extra
    input checking, this would allow custom entries to be
    inserted in /etc/mtab. (CVE-2010-0296)

  - The strfmon() function contains an integer overflow
    vulnerability in width specifiers handling that could be
    triggered by an attacker that can control the format
    string passed to strfmon(). (CVE-2008-1391)

Also one non-security issue was fixed: - nscd in the paranoia mode
would crash on the periodic restart in case one of the databases was
disabled in the nscd configuration.

In addition, the timezone information was updated to the level of
2010l, including the following changes :

  - Africa/Cairo (Egypt) and Asia/Gaza (Palestine) do not
    use daylight saving during the month of Ramadan in order
    to prevent Muslims from fasting one hour longer.
    http://www.timeanddate.com/news/time/egypt-ends-dst-2010
    .html
    http://www.timeanddate.com/news/time/westbank-gaza-end-d
    st-2010.html

  - Africa/Casablanca (Marocco) has spent the period from
    May 2 to Aug 8 using daylight saving. Marocco adopted
    regular daylight saving, but the start and end dates
    vary every year.
    http://www.timeanddate.com/news/time/morocco-starts-dst-
    2010.html

  - America/Argentina/San_Luis (Argentina region) local
    government did not terminate its DST period as planned
    and instead decided to extend its use of the UTC-3 time
    indefinitely.
    http://www.worldtimezone.com/dst_news/dst_news_argentina
    08.html

New zones :

  - America/Bahia_Banderas (Mexican state of Nayarit) has
    declared that it is to follow the UCT-6 time instead of
    UCT-7, with the aim to have the same time as the nearby
    city of Puerto Vallarta.
    http://www.worldtimezone.com/dst_news/dst_news_mexico08.
    html

Historical changes :

  - Asia/Taipei information on DST usage listed 1980 as one
    year using DST, which should read 1979 instead according
    to government resources.

  - Europe/Helsinki, before switching to Central European
    standard DST in 1983, trialled DST for two years.
    However, the database omitted to specify that in these
    trials of 1981 and 1982, switches have been made one
    hour earlier than in 1983.

Spelling changes in Micronesia: - Pacific/Truk has been renamed to
Pacific/Chuuk in 1989. - Pacific/Ponape has been renamed to
Pacific/Pohnpei in 1984."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2008-1391.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0296.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2010-0830.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply YOU patch number 12641.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2012 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 9 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SUSE9", reference:"glibc-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-devel-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-html-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-i18ndata-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-info-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-locale-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"glibc-profile-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"nscd-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", reference:"timezone-2.3.3-98.114")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-32bit-9-201008251911")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-devel-32bit-9-201008251304")) flag++;
if (rpm_check(release:"SUSE9", cpu:"x86_64", reference:"glibc-locale-32bit-9-201008251304")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
