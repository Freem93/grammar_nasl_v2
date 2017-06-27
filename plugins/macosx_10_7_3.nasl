#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(57797);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2011-1148",
    "CVE-2011-1167",
    "CVE-2011-1657",
    "CVE-2011-1752",
    "CVE-2011-1783",
    "CVE-2011-1921",
    "CVE-2011-1938",
    "CVE-2011-2192",
    "CVE-2011-2202",
    "CVE-2011-2483",
    "CVE-2011-2895",
    "CVE-2011-2937",
    "CVE-2011-3182",
    "CVE-2011-3189",
    "CVE-2011-3246",
    "CVE-2011-3248",
    "CVE-2011-3249",
    "CVE-2011-3250",
    "CVE-2011-3256",
    "CVE-2011-3267",
    "CVE-2011-3268",
    "CVE-2011-3328",
    "CVE-2011-3348",
    "CVE-2011-3389",
    "CVE-2011-3422",
    "CVE-2011-3441",
    "CVE-2011-3444",
    "CVE-2011-3446",
    "CVE-2011-3447",
    "CVE-2011-3448",
    "CVE-2011-3449",
    "CVE-2011-3450",
    "CVE-2011-3452",
    "CVE-2011-3453",
    "CVE-2011-3457",
    "CVE-2011-3458",
    "CVE-2011-3459",
    "CVE-2011-3460",
    "CVE-2011-3462",
    "CVE-2011-3463"
  );
  script_bugtraq_id(
    46843,
    46951,
    47950,
    48091,
    48259,
    48434,
    49124,
    49229,
    49241,
    49249,
    49252,
    49376,
    49429,
    49616,
    49744,
    49778,
    50115,
    50155,
    50400,
    50401,
    50404,
    50641,
    51807,
    51808,
    51809,
    51810,
    51811,
    51812,
    51813,
    51814,
    51815,
    51816,
    51817,
    51818,
    51819,
    51832
  );
  script_osvdb_id(
    71256,
    72644,
    73113,
    73218,
    73245,
    73246,
    73247,
    73328,
    73686,
    74567,
    74726,
    74738,
    74739,
    74742,
    74743,
    74829,
    74927,
    75200,
    75446,
    75647,
    75676,
    76322,
    76324,
    76541,
    76542,
    76543,
    77015,
    78313,
    78802,
    78803,
    78804,
    78805,
    78806,
    78807,
    78808,
    78809,
    78810,
    78811,
    78812,
    78813,
    78814,
    78815
  );
  script_xref(name:"CERT", value:"403593");
  script_xref(name:"CERT", value:"410281");
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"ZDI", value:"ZDI-12-058");
  script_xref(name:"ZDI", value:"ZDI-12-103");
  script_xref(name:"ZDI", value:"ZDI-12-130");

  script_name(english:"Mac OS X 10.7.x < 10.7.3 Multiple Vulnerabilities (BEAST)");
  script_summary(english:"Check the version of Mac OS X.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.7.x that is prior
to 10.7.3. The newer version contains multiple security-related fixes
for the following components :

  - Address Book
  - Apache
  - ATS
  - CFNetwork
  - CoreMedia
  - CoreText
  - CoreUI
  - curl
  - Data Security
  - dovecot
  - filecmds
  - ImageIO
  - Internet Sharing
  - Libinfo
  - libresolv
  - libsecurity
  - OpenGL
  - PHP
  - QuickTime
  - Subversion
  - Time Machine
  - WebDAV Sharing
  - Webmail
  - X11"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-058/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-103/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-130/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/59");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT5130"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2012/Feb/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.7.3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

  exit(0);
}

os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  if (isnull(os)) exit(0, "The 'Host/OS' KB item is missing.");
  if ("Mac OS X" >!< os) exit(0, "The host does not appear to be running Mac OS X.");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


if (ereg(pattern:"Mac OS X 10\.7($|\.[0-2]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
