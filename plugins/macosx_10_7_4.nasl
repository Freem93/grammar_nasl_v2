#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);    # Avoid problems with large number of xrefs.


include("compat.inc");


if (description)
{
  script_id(59066);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/10/03 20:33:39 $");

  script_cve_id(
    "CVE-2011-1004",
    "CVE-2011-1005",
    "CVE-2011-1777",
    "CVE-2011-1778",
    "CVE-2011-1944",
    "CVE-2011-2821",
    "CVE-2011-2834",
    "CVE-2011-2895",
    "CVE-2011-3212",
    "CVE-2011-3389",
    "CVE-2011-3919",
    "CVE-2011-4566",
    "CVE-2011-4815",
    "CVE-2011-4885",
    "CVE-2012-0036",
    "CVE-2012-0642",
    "CVE-2012-0649",
    "CVE-2012-0652",
    "CVE-2012-0654",
    "CVE-2012-0655",
    "CVE-2012-0656",
    "CVE-2012-0657",
    "CVE-2012-0658",
    "CVE-2012-0659",
    "CVE-2012-0660",
    "CVE-2012-0661",
    "CVE-2012-0662",
    "CVE-2012-0675",
    "CVE-2012-0830"
  );
  script_bugtraq_id(
    46458,
    46460,
    47737,
    48056,
    49124,
    49279,
    49658,
    49778,
    50907,
    51193,
    51198,
    51300,
    51665,
    51830,
    52364,
    53456,
    53457,
    53459,
    53462,
    53465,
    53466,
    53467,
    53468,
    53469,
    53470,
    53471,
    53473
  );
  script_osvdb_id(
    70957,
    70958,
    73248,
    74695,
    74829,
    74927,
    75560,
    76362,
    77446,
    77464,
    77465,
    78115,
    78118,
    78148,
    78512,
    78819,
    79970,
    81930,
    81931,
    81932,
    81933,
    82016,
    82207,
    82220,
    82222,
    82223,
    82224,
    82225,
    82226
  );
  script_xref(name:"TRA", value:"TRA-2012-02");
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"ZDI", value:"ZDI-12-135");

  script_name(english:"Mac OS X 10.7.x < 10.7.4 Multiple Vulnerabilities (BEAST)");
  script_summary(english:"Check the version of Mac OS X.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host is missing a Mac OS X update that fixes several
security issues."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is running a version of Mac OS X 10.7.x that is prior
to 10.7.4. The newer version contains numerous security-related fixes
for the following components :

  - Login Window
  - Bluetooth
  - curl
  - HFS
  - Kernel
  - libarchive
  - libsecurity
  - libxml
  - LoginUIFramework
  - PHP
  - Quartz Composer
  - QuickTime
  - Ruby
  - Security Framework
  - Time Machine
  - X11

Note that this update addresses the recent FileVault password
vulnerability, in which user passwords are stored in plaintext to a
system-wide debug log if the legacy version of FileVault is used to
encrypt user directories after a system upgrade to Lion. Since the
patch only limits further exposure, though, we recommend that all
users on the system change their passwords if user folders were
encrypted using the legacy version of FileVault prior to and after an
upgrade to OS X 10.7."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2012-02");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5281");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/May/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-135");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2012/Aug/64");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade to Mac OS X 10.7.4 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/10");

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


if (ereg(pattern:"Mac OS X 10\.7($|\.[0-3]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
