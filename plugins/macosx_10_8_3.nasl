#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(65577);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/16 14:02:53 $");

  script_cve_id(
    "CVE-2011-3058",
    "CVE-2012-2088",
    "CVE-2012-3749",
    "CVE-2012-3756",
    "CVE-2013-0963",
    "CVE-2013-0966",
    "CVE-2013-0967",
    "CVE-2013-0969",
    "CVE-2013-0970",
    "CVE-2013-0971",
    "CVE-2013-0976"
  );
  script_bugtraq_id(
    52762,
    54270,
    56361,
    56552,
    57598,
    58509,
    58512,
    58513,
    58515,
    58516,
    58517
  );
  script_osvdb_id(
    80736,
    83628,
    86871,
    87091,
    89660,
    91295,
    91296,
    91297,
    91298,
    91299,
    91300
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-14-1");

  script_name(english:"Mac OS X 10.8.x < 10.8.3 Multiple Vulnerabilities");
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
to 10.8.3. The newer version contains multiple security-related fixes
for the following components :

  - Apache
  - CoreTypes
  - International Components for Unicode
  - Identity Services
  - ImageIO
  - IOAcceleratorFamily
  - Kernel
  - Login Window
  - Messages
  - PDFKit
  - QuickTime
  - Security

Note that the update also runs a malware removal tool that will remove
the most common variants of malware."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-055/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5672");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526003/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/15");

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


if (ereg(pattern:"Mac OS X 10\.8($|\.[0-2]([^0-9]|$))", string:os)) security_hole(0);
else exit(0, "The host is not affected as it is running "+os+".");
