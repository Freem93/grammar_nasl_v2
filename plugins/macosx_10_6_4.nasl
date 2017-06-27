#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(47023);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_cve_id(
    "CVE-2009-1578",
    "CVE-2009-1579",
    "CVE-2009-1580",
    "CVE-2009-1581",
    "CVE-2009-2964",
    "CVE-2009-4212",
    "CVE-2010-0186",
    "CVE-2010-0187",
    "CVE-2010-0283",
    "CVE-2010-0302",
    "CVE-2010-0540",
    "CVE-2010-0541",
    "CVE-2010-0545",
    "CVE-2010-0546",
    "CVE-2010-0734",
    "CVE-2010-1320",
    "CVE-2010-1373",
    "CVE-2010-1374",
    "CVE-2010-1376",
    "CVE-2010-1377",
    "CVE-2010-1379",
    "CVE-2010-1380",
    "CVE-2010-1381",
    "CVE-2010-1382",
    "CVE-2010-1411",
    "CVE-2010-1748",
    "CVE-2010-1816",
    "CVE-2010-1821"
  );
  script_bugtraq_id(
    34916,
    36196,
    37749,
    38198,
    38200,
    38260,
    38510,
    39599,
    40886,
    40887,
    40888,
    40889,
    40892,
    40893,
    40895,
    40897,
    40902,
    40903,
    40905
  );
  script_osvdb_id(
    54504,
    54505,
    54506,
    54507,
    54508,
    57001,
    60204,
    61795,
    62217,
    62300,
    62370,
    62391,
    63975,
    65296,
    65555,
    65556,
    65558,
    65559,
    65560,
    65561,
    65563,
    65564,
    65565,
    65566,
    65567,
    65568,
    65569,
    156002,
    156003
  );

  script_name(english:"Mac OS X 10.6.x < 10.6.4 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes various
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.6.x that is prior
to 10.6.4.

Mac OS X 10.6.4 contains security fixes for the following components :

  - CUPS
  - DesktopServices
  - Flash Player plug-in
  - Folder Manager
  - Help Viewer
  - iChat
  - ImageIO
  - Kerberos
  - Kernel
  - libcurl
  - Network Authorization
  - Open Directory
  - Printer Setup
  - Printing
  - Ruby
  - SMB File Server
  - SquirrelMail
  - Wiki Server"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://support.apple.com/kb/HT4188"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://lists.apple.com/archives/security-announce/2010/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.6.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 79, 94, 189, 287, 352, 399);
  script_set_attribute(attribute:"vuln_publication_date", value:"2009/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/15");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
 
  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");

 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if (!os)
{
  os = get_kb_item("Host/OS");
  if (isnull(os)) exit(1, "The 'Host/OS' KB item is missing.");

  c = get_kb_item("Host/OS/Confidence");
  if (c <= 70) exit(1, "Can't determine the host's OS with sufficient confidence.");
}
if (!os) exit(0, "The 'Host/MacOSX/Version' KB item is missing.");


if (ereg(pattern:"Mac OS X 10\.6($|\.[0-3]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
