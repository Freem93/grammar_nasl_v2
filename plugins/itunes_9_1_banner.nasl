#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45391);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id(
    "CVE-2009-2285",
    "CVE-2010-0040",
    "CVE-2010-0041",
    "CVE-2010-0042",
    "CVE-2010-0043",
    "CVE-2010-0531",
    "CVE-2010-0532",
    "CVE-2010-1768",
    "CVE-2010-1795"
  );
  script_bugtraq_id(
    38673,
    38674,
    38676,
    38677,
    39092,
    39113,
    42538,
    42541
  );
  script_osvdb_id(
    55265,
    62933,
    62934,
    62935,
    62936,
    62949,
    62950,
    63449,
    63450,
    67329,
    67332
  );

  script_name(english:"Apple iTunes < 9.1 Multiple Vulnerabilities (uncredentialed check)");
  script_summary(english:"Checks the version of iTunes.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a multimedia application that has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Apple iTunes on the remote host is prior to version
9.1. It is, therefore, affected by multiple vulnerabilities :

  - A buffer underflow in ImageIO's handling of TIFF images
    can lead to a denial of service or arbitrary code
    execution. (CVE-2009-2285)

  - An integer overflow in the application's handling of
    images with an embedded color profile can lead to a
    denial of service or arbitrary code execution.
    (CVE-2010-0040)

  - An uninitialized memory access vulnerability in
    ImageIO's handling of BMP images can result in the
    sending of sensitive data from Safari's memory to
    a website under an attacker's control. (CVE-2010-0041)

  - An uninitialized memory access vulnerability in
    ImageIO's handling of TIFF images can result in the
    sending of sensitive data from Safari's memory to
    a website under an attacker's control. (CVE-2010-0042)

  - A memory corruption vulnerability in the ImageIO's
    handling of TIFF images can lead to a denial of
    service or arbitrary code execution. (CVE-2010-0043)

  - An infinite loop vulnerability in the application's
    handling of imported MP4 podcast files can lead to a
    denial of service or arbitrary code execution.
    (CVE-2010-0531)

  - A race condition during the installation process
    allows a local attacker to modify an unspecified file
    which can then be executed with SYSTEM privileges.
    (CVE-2010-0532)

  - A path searching vulnerability exists that allows code
    execution if an attacker places a specially crafted DLL
    in a directory and has a user open another file using
    iTunes in that directory. (CVE-2010-1795)

  - Syncing a mobile device can allow a local attacker to
    gain the privileges of the console user due to an
    insecure file operation in the handling of log files.
    (CVE-2010-1768)");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4105");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2010/Mar/msg00003.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/19388");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 9.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("itunes_sharing.nasl");
  script_require_keys("iTunes/sharing");
  script_require_ports("Services/www", 3689);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:3689, embedded:TRUE, ignore_broken:TRUE);

get_kb_item_or_exit("iTunes/" + port + "/enabled");

type = get_kb_item_or_exit("iTunes/" + port + "/type");
source = get_kb_item_or_exit("iTunes/" + port + "/source");
version = get_kb_item_or_exit("iTunes/" + port + "/version");

if (type == 'AppleTV') audit(AUDIT_LISTEN_NOT_VULN, "iTunes on AppleTV", port, version);

fixed_version = "9.1";

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source     : ' + source +
             '\n  Installed version  : ' + version +
             '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_LISTEN_NOT_VULN, "iTunes", port, version);
