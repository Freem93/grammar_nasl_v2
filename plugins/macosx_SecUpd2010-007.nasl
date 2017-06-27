#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(50549);
  script_version("$Revision: 1.47 $");
  script_cvs_date("$Date: 2016/11/28 21:06:39 $");

  script_cve_id(
    "CVE-2008-4546",
    "CVE-2009-0796",
    "CVE-2009-0946",
    "CVE-2009-2624",
    "CVE-2009-3793",
    "CVE-2009-4134",
    "CVE-2010-0105",
    "CVE-2010-0205",
    "CVE-2010-0209",
    "CVE-2010-0397",
    "CVE-2010-1205",
    "CVE-2010-1297",
    "CVE-2010-1449",
    "CVE-2010-1450",
    "CVE-2010-1752",
    "CVE-2010-1811",
    "CVE-2010-1828",
    "CVE-2010-1829",
    "CVE-2010-1830",
    "CVE-2010-1831",
    "CVE-2010-1832",
    "CVE-2010-1836",
    "CVE-2010-1837",
    "CVE-2010-1838",
    "CVE-2010-1840",
    "CVE-2010-1841",
    "CVE-2010-1845",
    "CVE-2010-1846",
    "CVE-2010-1848",
    "CVE-2010-1849",
    "CVE-2010-1850",
    "CVE-2010-2160",
    "CVE-2010-2161",
    "CVE-2010-2162",
    "CVE-2010-2163",
    "CVE-2010-2164",
    "CVE-2010-2165",
    "CVE-2010-2166",
    "CVE-2010-2167",
    "CVE-2010-2169",
    "CVE-2010-2170",
    "CVE-2010-2171",
    "CVE-2010-2172",
    "CVE-2010-2173",
    "CVE-2010-2174",
    "CVE-2010-2175",
    "CVE-2010-2176",
    "CVE-2010-2177",
    "CVE-2010-2178",
    "CVE-2010-2179",
    "CVE-2010-2180",
    "CVE-2010-2181",
    "CVE-2010-2182",
    "CVE-2010-2183",
    "CVE-2010-2184",
    "CVE-2010-2185",
    "CVE-2010-2186",
    "CVE-2010-2187",
    "CVE-2010-2188",
    "CVE-2010-2189",
    "CVE-2010-2213",
    "CVE-2010-2214",
    "CVE-2010-2215",
    "CVE-2010-2216",
    "CVE-2010-2249",
    "CVE-2010-2484",
    "CVE-2010-2497",
    "CVE-2010-2498",
    "CVE-2010-2499",
    "CVE-2010-2500",
    "CVE-2010-2519",
    "CVE-2010-2520",
    "CVE-2010-2531",
    "CVE-2010-2805",
    "CVE-2010-2806",
    "CVE-2010-2807",
    "CVE-2010-2808",
    "CVE-2010-2884",
    "CVE-2010-2941",
    "CVE-2010-3053",
    "CVE-2010-3054",
    "CVE-2010-3636",
    "CVE-2010-3638",
    "CVE-2010-3639",
    "CVE-2010-3640",
    "CVE-2010-3641",
    "CVE-2010-3642",
    "CVE-2010-3643",
    "CVE-2010-3644",
    "CVE-2010-3645",
    "CVE-2010-3646",
    "CVE-2010-3647",
    "CVE-2010-3648",
    "CVE-2010-3649",
    "CVE-2010-3650",
    "CVE-2010-3652",
    "CVE-2010-3654",
    "CVE-2010-3783",
    "CVE-2010-3784",
    "CVE-2010-3785",
    "CVE-2010-3796",
    "CVE-2010-3797",
    "CVE-2010-3976",
    "CVE-2010-4010"
  );
  script_bugtraq_id(
    31537,
    34383,
    34550,
    38478,
    39658,
    40361,
    40363,
    40365,
    40586,
    40779,
    40780,
    40781,
    40782,
    40783,
    40784,
    40785,
    40786,
    40787,
    40788,
    40789,
    40790,
    40791,
    40792,
    40793,
    40794,
    40795,
    40796,
    40797,
    40798,
    40799,
    40800,
    40801,
    40802,
    40803,
    40805,
    40806,
    40807,
    40808,
    40809,
    41049,
    41174,
    42285,
    42621,
    42624,
    44504,
    44530,
    44671,
    44729,
    44800,
    44802,
    44804,
    44806,
    44807,
    44808,
    44812,
    44814,
    44815,
    44816,
    44817,
    44819,
    44822,
    44829,
    44832,
    44833,
    44835,
    99999
  );
  script_osvdb_id(
    50073,
    53289,
    54068,
    54069,
    54070,
    61875,
    62670,
    63078,
    64123,
    64586,
    64587,
    64588,
    64965,
    64966,
    64967,
    65141,
    65532,
    65572,
    65573,
    65574,
    65575,
    65576,
    65577,
    65578,
    65579,
    65580,
    65581,
    65582,
    65583,
    65584,
    65585,
    65586,
    65587,
    65588,
    65589,
    65590,
    65591,
    65592,
    65593,
    65594,
    65595,
    65596,
    65597,
    65598,
    65599,
    65600,
    65702,
    65852,
    65853,
    66119,
    66463,
    66464,
    66465,
    66466,
    66467,
    66468,
    66804,
    66805,
    67011,
    67057,
    67058,
    67059,
    67060,
    67061,
    67062,
    67302,
    67303,
    67304,
    67305,
    67306,
    67307,
    67929,
    68024,
    68736,
    68932,
    68951,
    69121,
    69122,
    69123,
    69124,
    69125,
    69126,
    69127,
    69128,
    69129,
    69130,
    69131,
    69132,
    69133,
    69134,
    69146,
    69152,
    69256,
    69257,
    69258,
    69259,
    69289,
    69292,
    69293,
    69294,
    69295,
    69296,
    69306,
    69307,
    69309,
    69310,
    69311,
    69321,
    69322,
    69324
  );

  script_name(english:"Mac OS X Multiple Vulnerabilities (Security Update 2010-007)");
  script_summary(english:"Check for the presence of Security Update 2010-007");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes security
issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.5 that does not
have Security Update 2010-007 applied. 

This security update contains fixes for the following products :

  - AFP Server
  - Apache mod_perl
  - ATS
  - CFNetwork
  - CoreGraphics
  - CoreText
  - CUPS
  - Directory Services
  - diskdev_cmds
  - Disk Images
  - Flash Player plug-in
  - gzip
  - ImageIO
  - Image RAW
  - MySQL
  - Password Server
  - PHP
  - Printing
  - python
  - QuickLook
  - Safari RSS
  - Wiki Server
  - X11"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4435"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Nov/msg00000.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install Security Update 2010-007 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-164");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Adobe Flash Player "Button" Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 189, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


uname = get_kb_item("Host/uname");
if (!uname) exit(0, "The 'Host/uname' KB item is missing.");

pat = "^.+Darwin.* ([0-9]+\.[0-9.]+).*$";
if (!ereg(pattern:pat, string:uname)) exit(0, "Can't identify the Darwin kernel version from the uname output ("+uname+").");


darwin = ereg_replace(pattern:pat, replace:"\1", string:uname);
if (ereg(pattern:"^9\.[0-8]\.", string:darwin))
{
  packages = get_kb_item("Host/MacOSX/packages/boms");
  if (!packages) exit(1, "The 'Host/MacOSX/packages/boms' KB item is missing.");

  if (egrep(pattern:"^com\.apple\.pkg\.update\.security\.(2010\.00[7-9]|201[1-9]\.[0-9]+)(\.leopard)?\.bom", string:packages)) 
    exit(0, "The host has Security Update 2010-007 or later installed and therefore is not affected.");
  else 
    security_hole(0);
}
else exit(0, "The host is running Darwin kernel version "+darwin+" and therefore is not affected.");
