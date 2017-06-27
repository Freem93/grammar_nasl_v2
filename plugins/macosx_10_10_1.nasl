#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79310);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/21 16:08:18 $");

  script_cve_id(
    "CVE-2014-4453",
    "CVE-2014-4458",
    "CVE-2014-4459",
    "CVE-2014-4460"
  );
  script_bugtraq_id(71135, 71139, 71144);
  script_osvdb_id(114729, 114732, 114735, 114736);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2014-11-17-2");

  script_name(english:"Mac OS X 10.10.x < 10.10.1 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X 10.10.x that is prior
to version 10.10.1. This update contains several security-related
fixes for the following components :

  - CFNetwork
  - Spotlight
  - System Profiler About This Mac
  - WebKit

Note that successful exploitation of the most serious of these issues
can result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT6591");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/534004/30/0/threaded");

  script_set_attribute(attribute:"solution", value:"Upgrade to Mac OS X 10.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/18");

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

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];
if (!ereg(pattern:"^10\.10([^0-9]|$)", string:version)) audit(AUDIT_OS_NOT, "Mac OS X 10.10", "Mac OS X "+version);

fixed_version = "10.10.1";
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
