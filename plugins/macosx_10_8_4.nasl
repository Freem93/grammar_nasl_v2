#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66808);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2011-1945",
    "CVE-2011-3207",
    "CVE-2011-3210",
    "CVE-2011-4108",
    "CVE-2011-4109",
    "CVE-2011-4576",
    "CVE-2011-4577",
    "CVE-2011-4619",
    "CVE-2012-0050",
    "CVE-2012-2110",
    "CVE-2012-2131",
    "CVE-2012-2333",
    "CVE-2012-4929",
    "CVE-2012-5519",
    "CVE-2013-0975",
    "CVE-2013-0982",
    "CVE-2013-0983",
    "CVE-2013-0985",
    "CVE-2013-0986",
    "CVE-2013-0987",
    "CVE-2013-0988",
    "CVE-2013-0989",
    "CVE-2013-0990",
    "CVE-2013-1024"
  );
  script_bugtraq_id(
    47888,
    49469,
    49471,
    51281,
    51563,
    53158,
    53212,
    53476,
    55704,
    56494,
    60099,
    60100,
    60101,
    60109,
    60331,
    60365,
    60366,
    60367,
    60368,
    60369
  );
  script_osvdb_id(
    74632,
    75229,
    75230,
    78186,
    78187,
    78188,
    78189,
    78190,
    78320,
    81223,
    81810,
    82110,
    85927,
    87635,
    93617,
    93618,
    93620,
    93623,
    93920,
    93921,
    93922,
    93924,
    93925,
    93926
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-04-1");

  script_name(english:"Mac OS X 10.8.x < 10.8.4 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is running a version of Mac OS X 10.8.x that is prior
to 10.8.4. The newer version contains multiple security-related fixes
for the following components :

  - CFNetwork
  - CoreAnimation
  - CoreMedia Playback
  - CUPS
  - Disk Management
  - OpenSSL
  - QuickDraw Manager
  - QuickTime
  - SMB"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-111/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-119/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-150/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5784");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526808/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.8.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/05");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item_or_exit("Host/OS");
  if ("Mac OS X" >!< os) audit(AUDIT_OS_NOT, "Mac OS X");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");


if (ereg(pattern:"Mac OS X 10\.8($|\.[0-3]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
