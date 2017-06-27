#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76317);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/04/21 16:08:19 $");

  script_cve_id(
    "CVE-2014-0015",
    "CVE-2014-1317",
    "CVE-2014-1355",
    "CVE-2014-1356",
    "CVE-2014-1357",
    "CVE-2014-1358",
    "CVE-2014-1359",
    "CVE-2014-1361",
    "CVE-2014-1370",
    "CVE-2014-1371",
    "CVE-2014-1372",
    "CVE-2014-1373",
    "CVE-2014-1375",
    "CVE-2014-1376",
    "CVE-2014-1377",
    "CVE-2014-1378",
    "CVE-2014-1379",
    "CVE-2014-1380",
    "CVE-2014-1381"
  );
  script_bugtraq_id(65270, 68272, 68274);
  script_osvdb_id(
    102715,
    108531,
    108545,
    108546,
    108547,
    108548,
    108549,
    108550,
    108551,
    108552,
    108553,
    108554,
    108555,
    108556,
    108557,
    108558,
    108559,
    108560,
    108561
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-06-30-2");

  script_name(english:"Mac OS X 10.9.x < 10.9.4 Multiple Vulnerabilities");
  script_summary(english:"Check the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes a certificate
validation weakness.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.9.x that is prior
to 10.9.4. This update contains several security-related fixes for the
following components :

  - Certificate Trust Policy
  - copyfile
  - curl
  - Dock
  - Graphics Driver
  - iBooks Commerce
  - Intel Graphics Driver
  - Intel Compute
  - IOAcceleratorFamily
  - IOReporting
  - Keychain
  - launchd
  - Secure Transport
  - Thunderbolt

Note that successful exploitation of the most serious issues could
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6296");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/532600/30/0/threaded");
  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.9.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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


match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9])+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.9([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.9", "Mac OS X "+version);

fixed_version = "10.9.4";
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
