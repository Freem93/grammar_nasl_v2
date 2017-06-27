#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52612);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/17 16:53:09 $");

  script_cve_id(
    "CVE-2010-1824",
    "CVE-2010-4008",
    "CVE-2010-4494",
    "CVE-2011-0111",
    "CVE-2011-0112",
    "CVE-2011-0113",
    "CVE-2011-0114",
    "CVE-2011-0115",
    "CVE-2011-0116",
    "CVE-2011-0117",
    "CVE-2011-0118",
    "CVE-2011-0119",
    "CVE-2011-0120",
    "CVE-2011-0121",
    "CVE-2011-0122",
    "CVE-2011-0123",
    "CVE-2011-0124",
    "CVE-2011-0125",
    "CVE-2011-0126",
    "CVE-2011-0127",
    "CVE-2011-0128",
    "CVE-2011-0129",
    "CVE-2011-0130",
    "CVE-2011-0131",
    "CVE-2011-0132",
    "CVE-2011-0133",
    "CVE-2011-0134",
    "CVE-2011-0135",
    "CVE-2011-0136",
    "CVE-2011-0137",
    "CVE-2011-0138",
    "CVE-2011-0139",
    "CVE-2011-0140",
    "CVE-2011-0141",
    "CVE-2011-0142",
    "CVE-2011-0143",
    "CVE-2011-0144",
    "CVE-2011-0145",
    "CVE-2011-0146",
    "CVE-2011-0147",
    "CVE-2011-0148",
    "CVE-2011-0149",
    "CVE-2011-0150",
    "CVE-2011-0151",
    "CVE-2011-0152",
    "CVE-2011-0153",
    "CVE-2011-0154",
    "CVE-2011-0155",
    "CVE-2011-0156",
    "CVE-2011-0160",
    "CVE-2011-0161",
    "CVE-2011-0163",
    "CVE-2011-0165",
    "CVE-2011-0166",
    "CVE-2011-0167",
    "CVE-2011-0168",
    "CVE-2011-0169"
  );
  script_bugtraq_id(
    44779,
    46677,
    46684,
    46686,
    46687,
    46688,
    46689,
    46690,
    46691,
    46692,
    46693,
    46694,
    46695,
    46696,
    46698,
    46699,
    46700,
    46701,
    46702,
    46704,
    46705,
    46706,
    46707,
    46708,
    46709,
    46710,
    46711,
    46712,
    46713,
    46714,
    46715,
    46716,
    46717,
    46718,
    46719,
    46720,
    46721,
    46722,
    46723,
    46724,
    46725,
    46726,
    46727,
    46728,
    46744,
    46745,
    46746,
    46747,
    46748,
    46749,
    46808,
    46809,
    46811,
    46814,
    46816
  );
  script_osvdb_id(
    68102,
    69163,
    69164,
    69165,
    69170,
    69205,
    69671,
    69673,
    70105,
    70106,
    70454,
    70456,
    70461,
    70465,
    70466,
    70990,
    71495,
    71496,
    71498,
    71499,
    71501,
    71502,
    71503,
    71504,
    71506,
    71508,
    71509,
    71510,
    71511,
    71512,
    71513,
    71514,
    71515,
    71516,
    71517,
    71525,
    71527,
    71528,
    71529,
    71530,
    71532,
    71533,
    71534,
    71535,
    71536,
    71537,
    71539,
    71541,
    71542,
    71547,
    73773,
    73774,
    75013,
    75253,
    75254,
    75255
  );

  script_name(english:"Mac OS X : Apple Safari < 5.0.4");
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
earlier than 5.0.4. As such, it is potentially affected by several
issues in the following components :

  - libxml

  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4566");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Mar/msg00004.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.0.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("macosx_Safari31.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.* (9\.[0-8]\.|10\.)", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "5.0.4";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
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
