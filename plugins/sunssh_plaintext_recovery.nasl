#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55992);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/14 20:33:27 $");

  script_cve_id(
    "CVE-2000-0525",
    "CVE-2000-1169",
    "CVE-2001-0361",
    "CVE-2001-0529",
    "CVE-2001-0572",
    "CVE-2001-0816",
    "CVE-2001-0872",
    "CVE-2001-1380",
    "CVE-2001-1382",
    "CVE-2001-1459",
    "CVE-2001-1507",
    "CVE-2001-1585",
    "CVE-2002-0083",
    "CVE-2002-0575",
    "CVE-2002-0639",
    "CVE-2002-0640",
    "CVE-2002-0765",
    "CVE-2003-0190",
    "CVE-2003-0386",
    "CVE-2003-0682",
    "CVE-2003-0693",
    "CVE-2003-0695",
    "CVE-2003-0786",
    "CVE-2003-0787",
    "CVE-2003-1562",
    "CVE-2004-0175",
    "CVE-2004-1653",
    "CVE-2004-2069",
    "CVE-2004-2760",
    "CVE-2005-2666",
    "CVE-2005-2797",
    "CVE-2005-2798",
    "CVE-2006-0225",
    "CVE-2006-4924",
    "CVE-2006-4925",
    "CVE-2006-5051",
    "CVE-2006-5052",
    "CVE-2006-5229",
    "CVE-2006-5794",
    "CVE-2007-2243",
    "CVE-2007-2768",
    "CVE-2007-3102",
    "CVE-2007-4752",
    "CVE-2008-1483",
    "CVE-2008-1657",
    "CVE-2008-3259",
    "CVE-2008-4109",
    "CVE-2008-5161"
  );
  script_bugtraq_id(32319);
  script_osvdb_id(
    341,
    504,
    642,
    688,
    730,
    781,
    839,
    1853,
    2109,
    2112,
    2114,
    2116,
    2140,
    2557,
    3456,
    3562,
    5113,
    5408,
    5536,
    6071,
    6072,
    6245,
    6248,
    6601,
    9550,
    9562,
    16567,
    18236,
    19141,
    19142,
    20216,
    22692,
    29152,
    29264,
    29266,
    29494,
    30232,
    32721,
    34600,
    34601,
    39165,
    39214,
    43371,
    43745,
    43911,
    47227,
    49386,
    50036
  );
  script_xref(name:"CERT", value:"958563");

  script_name(english:"SunSSH < 1.1.1 / 1.3 CBC Plaintext Disclosure");
  script_summary(english:"Checks SSH banner");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The SSH service running on the remote host has an information
disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of SunSSH running on the remote host has an information
disclosure vulnerability.  A design flaw in the SSH specification
could allow a man-in-the-middle attacker to recover up to 32 bits of
plaintext from an SSH-protected connection in the standard
configuration.  An attacker could exploit this to gain access to
sensitive information.

Note that this version of SunSSH is also prone to several additional
issues but Nessus did not test for them." );

  # http://web.archive.org/web/20090523091544/http://www.cpni.gov.uk/docs/vulnerability_advisory_ssh.txt
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?4984aeb9");
  # http://hub.opensolaris.org/bin/view/Community+Group+security/SSH#HHistoryofSunSSH
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b679208a");
  script_set_attribute(attribute:"see_also",value:"http://blogs.oracle.com/janp/entry/on_sunssh_versioning");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to SunSSH 1.1.1 / 1.3 or later"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 20, 22, 189, 200, 255, 264, 287, 310, 362, 399);
  script_set_attribute(attribute:"vuln_publication_date",value:"2008/11/17");
  script_set_attribute(attribute:"patch_publication_date",value:"2008/12/11");
  script_set_attribute(attribute:"plugin_publication_date",value:"2011/08/29");
  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# Ensure the port is open.
port = get_service(svc:"ssh", default:22, exit_on_fail:TRUE);

# Get banner for service.
banner = get_kb_item_or_exit("SSH/banner/" + port);

# Check that we're using SunSSH.
if ('sun_ssh' >!< tolower(banner))
  exit(0, "The SSH service on port " + port + " is not SunSSH.");

# Check the version in the banner.
match = eregmatch(string:banner, pattern:"sun_ssh[-_]([0-9.]+)$", icase:TRUE);
if (isnull(match))
  exit(1, "Could not parse the version string from the banner on port " + port + ".");
else
  version = match[1];

# the Oracle (Sun) blog above explains how the versioning works. we could
# probably explicitly check for each vulnerable version if it came down to it
if (
  ver_compare(ver:version, fix:'1.1.1', strict:FALSE) == -1 ||
  version == '1.2'
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + banner +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.1.1 / 1.3\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else exit(0, "The SunSSH server on port "+port+" is not affected as it's version "+version+".");
