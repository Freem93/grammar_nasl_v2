#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78550);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2011-2391",
    "CVE-2013-5150",
    "CVE-2013-6438",
    "CVE-2014-0098",
    "CVE-2014-3537",
    "CVE-2014-3566",
    "CVE-2014-4351",
    "CVE-2014-4364",
    "CVE-2014-4371",
    "CVE-2014-4373",
    "CVE-2014-4375",
    "CVE-2014-4380",
    "CVE-2014-4388",
    "CVE-2014-4391",
    "CVE-2014-4404",
    "CVE-2014-4405",
    "CVE-2014-4407",
    "CVE-2014-4408",
    "CVE-2014-4417",
    "CVE-2014-4418",
    "CVE-2014-4419",
    "CVE-2014-4420",
    "CVE-2014-4421",
    "CVE-2014-4422",
    "CVE-2014-4425",
    "CVE-2014-4426",
    "CVE-2014-4427",
    "CVE-2014-4428",
    "CVE-2014-4430",
    "CVE-2014-4431",
    "CVE-2014-4432",
    "CVE-2014-4433",
    "CVE-2014-4434",
    "CVE-2014-4435",
    "CVE-2014-4436",
    "CVE-2014-4437",
    "CVE-2014-4438",
    "CVE-2014-4439",
    "CVE-2014-4440",
    "CVE-2014-4441",
    "CVE-2014-4442",
    "CVE-2014-4443",
    "CVE-2014-4444",
    "CVE-2014-6271",
    "CVE-2014-7169"
  );
  script_bugtraq_id(
    62531,
    62573,
    66303,
    68788,
    69911,
    69912,
    69913,
    69919,
    69924,
    69927,
    69928,
    69934,
    69938,
    69939,
    69942,
    69944,
    69946,
    69947,
    69948,
    70103,
    70137,
    70574,
    70616,
    70618,
    70619,
    70620,
    70622,
    70623,
    70624,
    70625,
    70627,
    70628,
    70629,
    70630,
    70631,
    70632,
    70633,
    70635,
    70636,
    70637,
    70638,
    70640,
    70643,
    70894
  );
  script_osvdb_id(
    97438,
    97444,
    104579,
    104580,
    109070,
    111643,
    111667,
    111990,
    111991,
    112004,
    113251,
    113428,
    113429,
    113430,
    113431,
    113432,
    113433,
    113434,
    113435,
    113436,
    113437,
    113438,
    113439,
    113440,
    113441,
    113442,
    113445,
    113446,
    113447,
    113448,
    113449,
    113450,
    113451
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-10-16-1");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"EDB-ID", value:"35153");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Mac OS X < 10.10 Multiple Vulnerabilities (POODLE) (Shellshock)");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X is prior to version
10.10. This update contains several security-related fixes for the
following components :

  - 802.1X
  - AFP File Server
  - apache
  - App Sandbox
  - Bash
  - Bluetooth
  - Certificate Trust Policy
  - CFPreferences
  - CoreStorage
  - CUPS
  - Dock
  - fdesetup
  - iCloud Find My Mac
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit
  - Kernel
  - LaunchServices
  - LoginWindow
  - Mail
  - MCX Desktop Config Profiles
  - NetFS Client Framework
  - QuickTime
  - Safari
  - Secure Transport
  - Security
  - Security - Code Signing

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/kb/HT6535");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/533720/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  # http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e40f2f5a");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  # http://joystick.artificialstudios.org/mac-os-x-local-privilege-escalation/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1fbcc64");

  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X version 10.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache mod_cgi Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

fixed_version = "10.10";
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
