#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39338);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2006-2783",
    "CVE-2008-1588",
    "CVE-2008-2320",
    "CVE-2008-3281",
    "CVE-2008-3529",
    "CVE-2008-3632",
    "CVE-2008-4225",
    "CVE-2008-4226",
    "CVE-2008-4231",
    "CVE-2008-4409",
    "CVE-2009-1681",
    "CVE-2009-1682",
    "CVE-2009-1684",
    "CVE-2009-1685",
    "CVE-2009-1686",
    "CVE-2009-1687",
    "CVE-2009-1688",
    "CVE-2009-1689",
    "CVE-2009-1690",
    "CVE-2009-1691",
    "CVE-2009-1693",
    "CVE-2009-1694",
    "CVE-2009-1695",
    "CVE-2009-1696",
    "CVE-2009-1697",
    "CVE-2009-1698",
    "CVE-2009-1699",
    "CVE-2009-1700",
    "CVE-2009-1701",
    "CVE-2009-1702",
    "CVE-2009-1703",
    "CVE-2009-1704",
    "CVE-2009-1708",
    "CVE-2009-1709",
    "CVE-2009-1710",
    "CVE-2009-1711",
    "CVE-2009-1712",
    "CVE-2009-1713",
    "CVE-2009-1714",
    "CVE-2009-1715",
    "CVE-2009-1718",
    "CVE-2009-2420",
    "CVE-2009-2421"
  );
  script_bugtraq_id(
    30487,
    31092,
    32326,
    33276,
    35260,
    35270,
    35271,
    35272,
    35283,
    35284,
    35309,
    35310,
    35311,
    35315,
    35317,
    35318,
    35319,
    35320,
    35321,
    35322,
    35325,
    35327,
    35328,
    35330,
    35331,
    35332,
    35333,
    35334,
    35340,
    35344,
    35348,
    35349,
    35350,
    35351,
    35353,
    35481,
    35482
  );
  script_osvdb_id(
    26314,
    47286,
    47636,
    48158,
    48472,
    48569,
    48754,
    49992,
    49993,
    50028,
    54972,
    54973,
    54975,
    54981,
    54982,
    54983,
    54984,
    54985,
    54986,
    54987,
    54988,
    54989,
    54991,
    54992,
    54993,
    54994,
    54996,
    55004,
    55005,
    55006,
    55008,
    55009,
    55010,
    55011,
    55013,
    55014,
    55015,
    55022,
    55023,
    55027,
    55769,
    55783
  );

  script_name(english:"Mac OS X : Apple Safari < 4.0");
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
earlier than 4.0.  As such, it is potentially affected by numerous
issues in the following components :

  - CFNetwork
  - libxml
  - Safari
  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT3613");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2009/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/17079");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 94, 119, 189, 200, 255, 310, 399);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

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
if (!egrep(pattern:"Darwin.* (8\.|9\.([0-6]\.|7\.0))", string:uname)) audit(AUDIT_OS_NOT, "Mac OS X 10.4 / 10.5");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

fixed_version = "4.0";

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
