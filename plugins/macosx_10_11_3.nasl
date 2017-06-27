#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88047);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/16 16:21:30 $");

  script_cve_id(
    "CVE-2015-7995",
    "CVE-2016-1716",
    "CVE-2016-1717",
    "CVE-2016-1718",
    "CVE-2016-1719",
    "CVE-2016-1720",
    "CVE-2016-1721",
    "CVE-2016-1722",
    "CVE-2016-1729"
  );
  script_osvdb_id(
    126901,
    133138,
    133139,
    133140,
    133141,
    133142,
    133153,
    133154,
    133155
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2016-01-19-2");

  script_name(english:"Mac OS X 10.11.x < 10.11.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Mac OS X.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a Mac OS X update that fixes multiple
security vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Mac OS X that is 10.11.x prior
to 10.11.3. It is, therefore, affected by multiple vulnerabilities in
the following components :

  - AppleGraphicsPowerManagement
  - Disk Images
  - IOAcceleratorFamily
  - IOHIDFamily
  - IOKit
  - Kernel
  - libxslt
  - OSA Scripts
  - syslog

Note that successful exploitation of the most serious issues can
result in arbitrary code execution.");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT205731");
  # https://lists.apple.com/archives/security-announce/2016/Jan/msg00003.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3fa4477");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mac OS X version 10.11.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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
  if (c <= 70) exit(1, "Cannot determine the host's OS with sufficient confidence.");
}
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

match = eregmatch(pattern:"Mac OS X ([0-9]+(\.[0-9]+)+)", string:os);
if (isnull(match)) exit(1, "Failed to parse the Mac OS X version ('" + os + "').");

version = match[1];

if (
  version !~ "^10\.11([^0-9]|$)"
) audit(AUDIT_OS_NOT, "Mac OS X 10.11 or later", "Mac OS X "+version);

fixed_version = "10.11.3";
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
else exit(0, "The host is not affected since it is running Mac OS X "+version+".");
