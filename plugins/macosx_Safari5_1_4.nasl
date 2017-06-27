#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58322);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id(
    "CVE-2011-2825",
    "CVE-2011-2833",
    "CVE-2011-2846",
    "CVE-2011-2847",
    "CVE-2011-2854",
    "CVE-2011-2855",
    "CVE-2011-2857",
    "CVE-2011-2860",
    "CVE-2011-2866",
    "CVE-2011-2867",
    "CVE-2011-2868",
    "CVE-2011-2869",
    "CVE-2011-2870",
    "CVE-2011-2871",
    "CVE-2011-2872",
    "CVE-2011-2873",
    "CVE-2011-2877",
    "CVE-2011-3881",
    "CVE-2011-3885",
    "CVE-2011-3886",
    "CVE-2011-3888",
    "CVE-2011-3897",
    "CVE-2011-3908",
    "CVE-2011-3909",
    "CVE-2011-3928",
    "CVE-2012-0585",
    "CVE-2012-0586",
    "CVE-2012-0587",
    "CVE-2012-0588",
    "CVE-2012-0589",
    "CVE-2012-0590",
    "CVE-2012-0591",
    "CVE-2012-0592",
    "CVE-2012-0593",
    "CVE-2012-0594",
    "CVE-2012-0595",
    "CVE-2012-0596",
    "CVE-2012-0597",
    "CVE-2012-0598",
    "CVE-2012-0599",
    "CVE-2012-0600",
    "CVE-2012-0601",
    "CVE-2012-0602",
    "CVE-2012-0603",
    "CVE-2012-0604",
    "CVE-2012-0605",
    "CVE-2012-0606",
    "CVE-2012-0607",
    "CVE-2012-0608",
    "CVE-2012-0609",
    "CVE-2012-0610",
    "CVE-2012-0611",
    "CVE-2012-0612",
    "CVE-2012-0613",
    "CVE-2012-0614",
    "CVE-2012-0615",
    "CVE-2012-0616",
    "CVE-2012-0617",
    "CVE-2012-0618",
    "CVE-2012-0619",
    "CVE-2012-0620",
    "CVE-2012-0621",
    "CVE-2012-0622",
    "CVE-2012-0623",
    "CVE-2012-0624",
    "CVE-2012-0625",
    "CVE-2012-0626",
    "CVE-2012-0627",
    "CVE-2012-0628",
    "CVE-2012-0629",
    "CVE-2012-0630",
    "CVE-2012-0631",
    "CVE-2012-0632",
    "CVE-2012-0633",
    "CVE-2012-0635",
    "CVE-2012-0636",
    "CVE-2012-0637",
    "CVE-2012-0638",
    "CVE-2012-0639",
    "CVE-2012-0640",
    "CVE-2012-0647",
    "CVE-2012-0648"
  );
  script_bugtraq_id(
    49279,
    49658,
    49938,
    50360,
    50642,
    51041,
    51641,
    52363,
    52365,
    52367,
    52419,
    52421,
    52423,
    52956,
    53148
  );
  script_osvdb_id(
    74694,
    75545,
    75547,
    75556,
    75557,
    75559,
    75562,
    76062,
    76067,
    76552,
    76556,
    76557,
    76558,
    76559,
    77037,
    77710,
    77711,
    78545,
    79905,
    79906,
    79907,
    79908,
    79909,
    79910,
    79911,
    79912,
    79913,
    79914,
    79915,
    79916,
    79917,
    79918,
    79919,
    79920,
    79921,
    79922,
    79923,
    79924,
    79925,
    79926,
    79927,
    79928,
    79929,
    79930,
    79931,
    79932,
    79933,
    79934,
    79935,
    79936,
    79937,
    79938,
    79939,
    79940,
    79941,
    79942,
    79943,
    79944,
    79945,
    79946,
    79947,
    79948,
    79949,
    79950,
    79951,
    79952,
    79953,
    79954,
    79955,
    79956,
    79957,
    79959,
    79960,
    79961,
    79962,
    79963,
    79964,
    79965,
    79966,
    79967,
    79968,
    79975,
    80175,
    80178,
    90387,
    90388,
    90389,
    90390,
    90446,
    90447,
    90448,
    90449,
    90450
  );

  script_name(english:"Mac OS X : Apple Safari < 5.1.4 Multiple Vulnerabilities");
  script_summary(english:"Check the Safari SourceVersion");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a web browser that is affected by several
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple Safari installed on the remote Mac OS X host is
earlier than 5.1.4.  Thus, it is potentially affected by several
issues :
 
  - Web page visits may be recorded in browser history even 
    when private browsing is active. (CVE-2012-0585)

  - Multiple cross-site scripting issues existed in WebKit. 
    (CVE-2011-3881, CVE-2012-0586, CVE-2012-0587, 
    CVE-2012-0588, CVE-2012-0589)

  - A cross-origin issue existed in WebKit, which may allow 
    cookies to be disclosed across origins. (CVE-2011-3887)

  - Visiting a maliciously crafted website and dragging 
    content with the mouse may lead to a cross-site 
    scripting attack. (CVE-2012-0590)

  - Multiple memory corruption issues existed in WebKit.
    (CVE-2011-2825, CVE-2011-2833, CVE-2011-2846, 
     CVE-2011-2847, CVE-2011-2854, CVE-2011-2855, 
     CVE-2011-2857, CVE-2011-2860, CVE-2011-2866, 
     CVE-2011-2867, CVE-2011-2868, CVE-2011-2869,
     CVE-2011-2870, CVE-2011-2871, CVE-2011-2872, 
     CVE-2011-2873, CVE-2011-2877, CVE-2011-3885, 
     CVE-2011-3888, CVE-2011-3897, CVE-2011-3908, 
     CVE-2011-3909, CVE-2011-3928, CVE-2012-0591,
     CVE-2012-0592, CVE-2012-0593, CVE-2012-0594, 
     CVE-2012-0595, CVE-2012-0596, CVE-2012-0597, 
     CVE-2012-0598, CVE-2012-0599, CVE-2012-0600, 
     CVE-2012-0601, CVE-2012-0602, CVE-2012-0603,
     CVE-2012-0604, CVE-2012-0605, CVE-2012-0606, 
     CVE-2012-0607, CVE-2012-0608, CVE-2012-0609, 
     CVE-2012-0610, CVE-2012-0611, CVE-2012-0612, 
     CVE-2012-0613, CVE-2012-0614, CVE-2012-0615,
     CVE-2012-0616, CVE-2012-0617, CVE-2012-0618, 
     CVE-2012-0619, CVE-2012-0620, CVE-2012-0621, 
     CVE-2012-0622, CVE-2012-0623, CVE-2012-0624, 
     CVE-2012-0625, CVE-2012-0626, CVE-2012-0627,
     CVE-2012-0628, CVE-2012-0629, CVE-2012-0630, 
     CVE-2012-0631, CVE-2012-0632, CVE-2012-0633, 
     CVE-2012-0635, CVE-2012-0636, CVE-2012-0637, 
     CVE-2012-0638, CVE-2012-0639, CVE-2012-0648)

   - Cookies may be set by third-parties, even when Safari 
     is configured to block them. (CVE-2012-0640)

   - If a site uses HTTP authentication and redirects to 
     another site, the authentication credentials may be 
     sent to the other site. (CVE-2012-0647)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-147/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/267");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5190");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Mar/msg00003.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.1.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks"); 

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

if (!ereg(pattern:"Mac OS X 10\.[67]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.6 / 10.7");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "5.1.4";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "Safari", version);
