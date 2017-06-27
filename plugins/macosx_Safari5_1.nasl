#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55638);
  script_version("$Revision: 1.44 $");
  script_cvs_date("$Date: 2016/11/28 21:06:38 $");

  script_cve_id(
    "CVE-2010-1823",
    "CVE-2010-3829",
    "CVE-2011-0164",
    "CVE-2011-0217",
    "CVE-2011-0218",
    "CVE-2011-0219",
    "CVE-2011-0221",
    "CVE-2011-0222",
    "CVE-2011-0223",
    "CVE-2011-0225",
    "CVE-2011-0232",
    "CVE-2011-0233",
    "CVE-2011-0234",
    "CVE-2011-0235",
    "CVE-2011-0237",
    "CVE-2011-0238",
    "CVE-2011-0240",
    "CVE-2011-0242",
    "CVE-2011-0244",
    "CVE-2011-0253",
    "CVE-2011-0254",
    "CVE-2011-0255",
    "CVE-2011-0981",
    "CVE-2011-0983",
    "CVE-2011-1107",
    "CVE-2011-1109",
    "CVE-2011-1114",
    "CVE-2011-1115",
    "CVE-2011-1117",
    "CVE-2011-1121",
    "CVE-2011-1188",
    "CVE-2011-1190",
    "CVE-2011-1203",
    "CVE-2011-1204",
    "CVE-2011-1288",
    "CVE-2011-1293",
    "CVE-2011-1295",
    "CVE-2011-1296",
    "CVE-2011-1449",
    "CVE-2011-1451",
    "CVE-2011-1453",
    "CVE-2011-1457",
    "CVE-2011-1462",
    "CVE-2011-1774",
    "CVE-2011-1797",
    "CVE-2011-3443"
  );
  script_bugtraq_id(
    43228,
    46262,
    46614,
    46703,
    46785,
    47029,
    47604,
    48820,
    48823,
    48824,
    48827,
    48839,
    48840,
    48841,
    48842,
    48843,
    48844,
    48845,
    48846,
    48847,
    48848,
    48849,
    48850,
    48851,
    48852,
    48853,
    48854,
    48855,
    48856,
    48857,
    48858,
    48859,
    48860
  );
  script_osvdb_id(
    68101,
    69497,
    70977,
    70980,
    70981,
    71524,
    72214,
    72216,
    72262,
    72263,
    72265,
    72272,
    72276,
    72278,
    72279,
    72284,
    72286,
    72303,
    72476,
    72478,
    72491,
    72492,
    73995,
    73996,
    73997,
    73998,
    73999,
    74000,
    74001,
    74002,
    74003,
    74004,
    74005,
    74006,
    74007,
    74008,
    74009,
    74010,
    74011,
    74012,
    74013,
    74014,
    74015,
    74016,
    74018,
    74019,
    79787
  );
  script_xref(name:"EDB-ID", value:"17575");
  script_xref(name:"EDB-ID", value:"17993");

  script_name(english:"Mac OS X : Apple Safari < 5.1 / 5.0.6");
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
earlier than 5.1 / 5.0.6. As such, it is potentially affected by
numerous issues in the following components :

  - Safari
  - WebKit"
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4808");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2011/Jul/msg00002.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple Safari 5.1 / 5.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-678");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple Safari Webkit libxslt Arbitrary File Creation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:safari");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

if (!ereg(pattern:"Mac OS X 10\.[56]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.5 / 10.6");


get_kb_item_or_exit("MacOSX/Safari/Installed");
path = get_kb_item_or_exit("MacOSX/Safari/Path", exit_code:1);
version = get_kb_item_or_exit("MacOSX/Safari/Version", exit_code:1);

if ("10.5" >< os) fixed_version = "5.0.5";
else fixed_version = "5.1";

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
