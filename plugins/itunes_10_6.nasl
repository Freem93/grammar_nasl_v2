#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(58319);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/10/27 15:03:54 $");

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
    "CVE-2011-3885",
    "CVE-2011-3888",
    "CVE-2011-3897",
    "CVE-2011-3908",
    "CVE-2011-3909",
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
    "CVE-2012-0634",
    "CVE-2012-0635",
    "CVE-2012-0636",
    "CVE-2012-0637",
    "CVE-2012-0638",
    "CVE-2012-0639",
    "CVE-2012-0648"
  );
  script_bugtraq_id(
    49279,
    49658,
    49938,
    50360,
    50642,
    51041,
    52363,
    52365,
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
    76556,
    76559,
    77037,
    77710,
    77711,
    77932,
    77933,
    77934,
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
    79958,
    79959,
    79960,
    79961,
    79962,
    79963,
    90387,
    90388,
    90389,
    90390,
    90446,
    90447,
    90448,
    90449,
    90450,
    94666
  );

  script_name(english:"Apple iTunes < 10.6 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains a multimedia application that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 10.6.  Thus, it is reportedly affected by numerous memory
corruption vulnerabilities in its WebKit component."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-147/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/267");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5191");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Mar/msg00000.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 10.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "10.6.0.40";

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  if (report_verbosity > 0)
  {
    path = get_kb_item("SMB/iTunes/Path");
    if (isnull(path)) path = 'n/a';

    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:get_kb_item("SMB/transport"), extra:report);
  }
  else security_hole(get_kb_item("SMB/transport"));
}
else exit(0, "The iTunes "+version+" install in "+path+" is not affected.");
