#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82699);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/28 21:06:37 $");

  script_cve_id(
    "CVE-2013-0118",
    "CVE-2013-5704",
    "CVE-2013-6438",
    "CVE-2013-6712",
    "CVE-2014-0098",
    "CVE-2014-0117",
    "CVE-2014-0118",
    "CVE-2014-0207",
    "CVE-2014-0226",
    "CVE-2014-0231",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-2497",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3523",
    "CVE-2014-3538",
    "CVE-2014-3569",
    "CVE-2014-3570",
    "CVE-2014-3571",
    "CVE-2014-3572",
    "CVE-2014-3587",
    "CVE-2014-3597",
    "CVE-2014-3668",
    "CVE-2014-3669",
    "CVE-2014-3670",
    "CVE-2014-3710",
    "CVE-2014-3981",
    "CVE-2014-4049",
    "CVE-2014-4380",
    "CVE-2014-4404",
    "CVE-2014-4405",
    "CVE-2014-4670",
    "CVE-2014-4698",
    "CVE-2014-5120",
    "CVE-2014-8275",
    "CVE-2014-8830",
    "CVE-2014-9298",
    "CVE-2015-0204",
    "CVE-2015-1069",
    "CVE-2015-1088",
    "CVE-2015-1089",
    "CVE-2015-1091",
    "CVE-2015-1093",
    "CVE-2015-1095",
    "CVE-2015-1096",
    "CVE-2015-1098",
    "CVE-2015-1099",
    "CVE-2015-1100",
    "CVE-2015-1101",
    "CVE-2015-1102",
    "CVE-2015-1103",
    "CVE-2015-1104",
    "CVE-2015-1105",
    "CVE-2015-1117",
    "CVE-2015-1118",
    "CVE-2015-1130",
    "CVE-2015-1131",
    "CVE-2015-1132",
    "CVE-2015-1133",
    "CVE-2015-1134",
    "CVE-2015-1135",
    "CVE-2015-1136",
    "CVE-2015-1137",
    "CVE-2015-1138",
    "CVE-2015-1139",
    "CVE-2015-1140",
    "CVE-2015-1141",
    "CVE-2015-1142",
    "CVE-2015-1143",
    "CVE-2015-1144",
    "CVE-2015-1145",
    "CVE-2015-1146",
    "CVE-2015-1147",
    "CVE-2015-1148",
    "CVE-2015-1160",
    "CVE-2015-1545",
    "CVE-2015-1546"
  );
  script_bugtraq_id(
    58128,
    64018,
    66233,
    66303,
    66550,
    67759,
    67765,
    67837,
    68007,
    68120,
    68238,
    68239,
    68241,
    68243,
    68348,
    68511,
    68513,
    68678,
    68740,
    68742,
    68745,
    68747,
    69322,
    69325,
    69375,
    69938,
    69942,
    69947,
    70611,
    70665,
    70666,
    70807,
    71934,
    71935,
    71936,
    71937,
    71939,
    71942,
    72328,
    72519,
    72584,
    73176,
    73981,
    73982,
    73984
  );
  script_osvdb_id(
    79681,
    90594,
    100440,
    104208,
    104502,
    104579,
    104580,
    105190,
    107559,
    107560,
    107725,
    107994,
    108463,
    108464,
    108465,
    108466,
    108467,
    108946,
    108947,
    109216,
    109230,
    109231,
    109232,
    109234,
    110250,
    110251,
    110292,
    111669,
    111990,
    111991,
    113421,
    113422,
    113423,
    113614,
    116072,
    116423,
    116792,
    116793,
    116794,
    116795,
    116796,
    117652,
    118031,
    118032,
    119688,
    120418,
    120419,
    120420,
    120421,
    120422,
    120423,
    120424,
    120425,
    120426,
    120427,
    120428,
    120429,
    120430,
    120431,
    120432,
    120433,
    120434,
    120435,
    120436,
    120437,
    120438,
    120439,
    120440,
    120441,
    120442,
    120443,
    120444,
    120445,
    120446,
    120447,
    120448,
    120449,
    120450,
    120451,
    120452,
    129433
  );
  script_xref(name:"CERT", value:"243585");
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2015-04-08-2");

  script_name(english:"Mac OS X 10.10.x < 10.10.3 Multiple Vulnerabilities (FREAK)");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.x that is prior
to 10.10.3. It is, therefore, affected multiple vulnerabilities in the
following components :

  - Admin Framework
  - Apache
  - ATS
  - Certificate Trust Policy
  - CFNetwork HTTPProtocol
  - CFNetwork Session
  - CFURL
  - CoreAnimation
  - FontParser
  - Graphics Driver
  - Hypervisor
  - ImageIO
  - IOHIDFamily
  - Kernel
  - LaunchServices
  - libnetcore
  - ntp
  - Open Directory Client
  - OpenLDAP
  - OpenSSL
  - PHP
  - QuickLook
  - SceneKit
  - ScreenSharing
  - Security - Code SIgning
  - UniformTypeIdentifiers
  - WebKit

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/en-us/HT204659");
  # http://prod.lists.apple.com/archives/security-announce/2015/Apr/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31b018c2");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.10.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apple OS X Rootpipe Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_ports("Host/MacOSX/Version", "Host/OS");

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

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.10([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.10", "Mac OS X "+version);

fixed_version = "10.10.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
    {
      report = '\n  Installed version : ' + version +
               '\n  Fixed version     : ' + fixed_version +
               '\n';
      security_hole(port:0, extra:report);
    }
    else security_hole(0);
    exit(0);
}
else exit(0, "The host is not affected as it is running Mac OS X "+version+".");
