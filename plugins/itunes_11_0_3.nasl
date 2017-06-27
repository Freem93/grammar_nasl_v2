#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66498);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/06/17 14:46:28 $");

  script_cve_id(
    "CVE-2012-2824",
    "CVE-2012-2857",
    "CVE-2012-3748",
    "CVE-2012-5112",
    "CVE-2013-0879",
    "CVE-2013-0912",
    "CVE-2013-0948",
    "CVE-2013-0949",
    "CVE-2013-0950",
    "CVE-2013-0951",
    "CVE-2013-0952",
    "CVE-2013-0953",
    "CVE-2013-0954",
    "CVE-2013-0955",
    "CVE-2013-0956",
    "CVE-2013-0958",
    "CVE-2013-0959",
    "CVE-2013-0960",
    "CVE-2013-0961",
    "CVE-2013-0991",
    "CVE-2013-0992",
    "CVE-2013-0993",
    "CVE-2013-0994",
    "CVE-2013-0995",
    "CVE-2013-0996",
    "CVE-2013-0997",
    "CVE-2013-0998",
    "CVE-2013-0999",
    "CVE-2013-1000",
    "CVE-2013-1001",
    "CVE-2013-1002",
    "CVE-2013-1003",
    "CVE-2013-1004",
    "CVE-2013-1005",
    "CVE-2013-1006",
    "CVE-2013-1007",
    "CVE-2013-1008",
    "CVE-2013-1010",
    "CVE-2013-1011",
    "CVE-2013-1014"
  );
  script_bugtraq_id(
    54203,
    54749,
    55867,
    56362,
    57576,
    57580,
    57581,
    57582,
    57584,
    57585,
    57586,
    57587,
    57588,
    57589,
    57590,
    58388,
    58495,
    58496,
    59941,
    59944,
    59953,
    59954,
    59955,
    59956,
    59957,
    59958,
    59959,
    59960,
    59963,
    59964,
    59965,
    59967,
    59970,
    59971,
    59972,
    59973,
    59974,
    59976,
    59977
  );
  script_osvdb_id(
    83238,
    83242,
    83243,
    83245,
    83246,
    83247,
    83250,
    83252,
    83254,
    83255,
    83256,
    83257,
    84369,
    84377,
    84380,
    86149,
    86873,
    89645,
    89646,
    89648,
    89649,
    89650,
    89651,
    89652,
    89653,
    89654,
    89655,
    89656,
    90521,
    91220,
    91429,
    91430,
    93175,
    93459,
    93470,
    93471,
    93472,
    93473,
    93474,
    93475,
    93476,
    93477,
    93478,
    93479,
    93480,
    93481,
    93482,
    93483,
    93484,
    93485,
    93486,
    93487,
    93488,
    93489
  );
  script_xref(name:"EDB-ID", value:"28081");

  script_name(english:"Apple iTunes < 11.0.3 Multiple Vulnerabilities (credentialed check)");
  script_summary(english:"Checks version of iTunes on Windows");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host contains an application that has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Apple iTunes installed on the remote Windows host is
older than 11.0.3.  It therefore is potentially affected by several
issues :

  - An error exists related to certificate validation
    that could allow disclosure of sensitive information
    and could allow the application to trust data from
    untrusted sources. (CVE-2013-1014)

  - The included version of WebKit contains several errors
    that could lead to memory corruption and possibly
    arbitrary code execution. The vendor notes one possible
    attack vector is a man-in-the-middle attack while the
    application browses the 'iTunes Store'.
    (CVE-2012-2824, CVE-2012-2857, CVE-2012-3748,
    CVE-2012-5112, CVE-2013-0879, CVE-2013-0912,
    CVE-2013-0948, CVE-2013-0949, CVE-2013-0950,
    CVE-2013-0951, CVE-2013-0952, CVE-2013-0953,
    CVE-2013-0954, CVE-2013-0955, CVE-2013-0956,
    CVE-2013-0958, CVE-2013-0959, CVE-2013-0960,
    CVE-2013-0961, CVE-2013-0991, CVE-2013-0992,
    CVE-2013-0993, CVE-2013-0994, CVE-2013-0995,
    CVE-2013-0996, CVE-2013-0997, CVE-2013-0998,
    CVE-2013-0999, CVE-2013-1000, CVE-2013-1001,
    CVE-2013-1002, CVE-2013-1003, CVE-2013-1004,
    CVE-2013-1005, CVE-2013-1006, CVE-2013-1007,
    CVE-2013-1008, CVE-2013-1010, CVE-2013-1011)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-107/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-108/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-109/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5766");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/May/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526623/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 11.0.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("itunes_detect.nasl");
  script_require_keys("SMB/iTunes/Version");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


version = get_kb_item_or_exit("SMB/iTunes/Version");
fixed_version = "11.0.3.42";
path = get_kb_item_or_exit("SMB/iTunes/Path");

if (ver_compare(ver:version, fix:fixed_version) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : '+path+
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+fixed_version+'\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "iTunes", version, path);
