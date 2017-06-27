#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99128);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/04/04 13:36:41 $");

  script_cve_id(
    "CVE-2007-6750",
    "CVE-2016-0751",
    "CVE-2017-2382"
  );
  script_bugtraq_id(
    21865,
    81800,
    97128
  );
  script_osvdb_id(
    121361,
    133587,
    154416
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-03-27-7");

  script_name(english:"macOS : macOS Server < 5.3 Multiple Vulnerabilities");
  script_summary(english:"Checks the macOS Server version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update for macOS Server.");
  script_set_attribute(attribute:"description", value:
"The version of macOS Server (formerly known as Mac OS X Server)
installed on the remote host is prior to 5.3. It is, therefore,
affected by the following vulnerabilities :

  - A denial of service vulnerability exists in the Apache
    HTTP server when handling a saturation of partial HTTP
    requests. An unauthenticated, remote attacker can
    exploit this to crash the daemon. (CVE-2007-6750)

  - A denial of service vulnerability exists in Action Pack
    in Ruby on Rails due to improper restrictions on the use
    of the MIME type cache when handling specially crafted
    HTTP accept headers. An unauthenticated, remote attacker
    can exploit this to cause the cache to grow
    indefinitely. (CVE-2016-0751)

  - An information disclosure vulnerability exists in the
    Wiki Server component due to improper checking of
    unspecified permissions. An unauthenticated, remote can
    exploit this to enumerate users. (CVE-2017-2382)");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT207604");
  # https://lists.apple.com/archives/security-announce/2017/Mar/msg00008.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4736faa");
  script_set_attribute(attribute:"solution", value:
"Upgrade to macOS Server version 5.3 or later. Note that macOS Server
version 5.3 is available only for macOS 10.12.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:os_x_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("macosx_server_services.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "macOS");

version = get_kb_item_or_exit("MacOSX/Server/Version");

fixed_version = "5.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  security_report_v4(
    port:0,
    severity:SECURITY_WARNING,
    extra:
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version +
      '\n'
  );
}
else audit(AUDIT_INST_VER_NOT_VULN, "macOS Server", version);
